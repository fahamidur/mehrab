# app.py
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime,timedelta
import os
import requests
from bs4 import BeautifulSoup
import time
import json
from urllib.parse import urljoin, urlparse
import re
from functools import wraps

# Import Flask-APScheduler
from flask_apscheduler import APScheduler

# Initialize Flask app
app = Flask(__name__)

# Configure secret key for session management and CSRF protection
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_super_secret_key_here')

# Configure SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Initialize APScheduler
scheduler = APScheduler()
app.config['SCHEDULER_API_ENABLED'] = True # Optional: enables scheduler API endpoint (e.g., /scheduler/jobs)
scheduler.init_app(app)

# --- Database Models ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(10), default='user', nullable=False)

    def set_password(self, password):
        """Hashes the password and stores it."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Checks if the provided password matches the stored hash."""
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"User('{self.username}', '{self.role}')"

class Article(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    summary = db.Column(db.Text, nullable=True)
    content = db.Column(db.Text, nullable=True)
    category = db.Column(db.String(50), nullable=True)
    source = db.Column(db.String(100), nullable=True)
    image_url = db.Column(db.String(255), nullable=True)
    time_to_read = db.Column(db.String(20), nullable=True)
    published_at = db.Column(db.DateTime, nullable=True)
    scraped_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    author = db.Column(db.String(100), nullable=True)
    tags = db.Column(db.String(255), nullable=True) # Stored as comma-separated string

    def __repr__(self):
        return f"Article('{self.title}', '{self.category}')"

    def to_dict(self):
        """Converts an Article object to a dictionary for JSON serialization."""
        return {
            'id': self.id,
            'title': self.title,
            'summary': self.summary,
            'content': self.content,
            'category': self.category,
            'source': self.source,
            'image': self.image_url,
            'timeToRead': self.time_to_read,
            'published_at': self.published_at.isoformat() if self.published_at else None,
            'scraped_at': self.scraped_at.isoformat(),
            'author': self.author,
            'tags': self.tags.split(',') if self.tags else [] # Split the comma-separated string back into a list
        }

# --- Flask-Login User Loader ---

@login_manager.user_loader
def load_user(user_id):
    """Loads a user from the database given their ID."""
    return User.query.get(int(user_id))

# --- Custom Decorators ---

def admin_required(f):
    """Decorator to restrict access to admin users only."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

# --- BBC News Scraper Class ---
class BBCNewsScraper:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept-Language': 'en-US,en;q=0.5'
        })
        self.base_url = 'https://www.bbc.com'
        self.visited_urls = set()
        self.rate_limit_delay = 0.5  # seconds between requests

    def get_page(self, url):
        """Fetch a page with error handling"""
        try:
            time.sleep(self.rate_limit_delay)
            response = self.session.get(url)
            response.raise_for_status()
            return response.text
        except requests.exceptions.RequestException as e:
            print(f"Error fetching {url}: {e}")
            return None

    def extract_category_links(self, category_url, max_pages=3):
        """Extract article links from a category page with pagination"""
        article_links = set()
        page_num = 1

        while page_num <= max_pages:
            page_to_scrape = category_url
            if page_num > 1:
                print(f"Limiting to first page for category {category_url} due to complex BBC pagination.")
                break

            print(f"Scraping category page {page_num}: {page_to_scrape}")
            html = self.get_page(page_to_scrape)
            if not html:
                print(f"Failed to fetch HTML for {page_to_scrape}")
                break

            soup = BeautifulSoup(html, 'html.parser')

            links = soup.select('a[data-testid="internal-link"], a.qa-heading-link, a.gs-c-promo-heading__link, a.ssrcss-ug1v3a-PromoLink')
            
            new_links = set()
            for link in links:
                href = link.get('href')
                if href:
                    full_url = urljoin(self.base_url, href)
                    if (re.match(r'.*/news/articles/[a-z0-9]+$', full_url) or
                        re.match(r'.*/news/[a-z0-9-]+-\d+$', full_url)) and \
                       'live' not in full_url.lower() and \
                       full_url != self.base_url and \
                       '/news/' in full_url:
                        new_links.add(full_url)
                    else:
                        print(f"Filtered out non-article link: {full_url}")

            if not new_links:
                print(f"No new article links found on page {page_to_scrape}")
                break

            article_links.update(new_links)
            page_num += 1

        print(f"Found {len(article_links)} unique article links from category {category_url}")
        return list(article_links)[:50]

    def _extract_title(self, soup):
        """Extract article title using common BBC selectors."""
        title_tag = soup.find('h1', class_='sc-f98b1ad2-0 dfvxux') or \
                    soup.find('h1', class_='ssrcss-gc7udw-StyledHeading e1fj1fc10') or \
                    soup.find('h1', class_='qa-story-headline') or \
                    soup.find('h1', class_='story-body__h1')
        return title_tag.get_text(strip=True) if title_tag else None

    def _extract_timestamp(self, soup):
        """Extract publication timestamp."""
        time_tag = soup.find('time', class_=re.compile(r'sc-801dd632-2|IvNnh')) or \
                   soup.find('time')
        if time_tag and 'datetime' in time_tag.attrs:
            try:
                return datetime.fromisoformat(time_tag['datetime'].replace('Z', '+00:00'))
            except ValueError:
                print(f"Warning: Could not parse datetime from '{time_tag['datetime']}'")
                pass
        return None

    def _extract_author(self, soup):
        """Extract author information."""
        author_div = soup.find('div', class_='ssrcss-68pt20-Text-TextContributorName') or \
                     soup.find('span', class_='qa-story-byline')
        return author_div.get_text(strip=True) if author_div else None

    def _extract_category_from_url(self, url):
        """Extract category name from URL (e.g., /news/technology -> technology)."""
        path = urlparse(url).path
        parts = [p for p in path.split('/') if p]
        if 'news' in parts:
            try:
                news_index = parts.index('news')
                if news_index + 1 < len(parts):
                    potential_category = parts[news_index + 1]
                    if not re.match(r'^[a-z0-9-]+-\d+$', potential_category) and \
                       not re.match(r'^\d+$', potential_category):
                        return potential_category.replace('-', ' ').title()
            except ValueError:
                pass
        return 'General'

    def _get_tag_from_url(self, url):
        """Extract and return only the approved tag from the URL"""
        if not url:
            return 'Politics'
            
        url = url.lower()
        if 'technology' in url:
            return 'Technology'
        elif 'politics' in url:
            return 'Politics'
        elif 'science' in url or 'environment' in url:
            return 'Science'
        elif 'business' in url:
            return 'Business'
        elif 'entertainment' in url or 'arts' in url:
            return 'Entertainment'
        elif 'sport' in url:
            return 'Sport'
        return 'Politics'

    def _extract_tags(self, soup, category):
        """Return empty list - tags are determined by URL only"""
        return []

    def _extract_content(self, soup):
        """Extract main article content paragraphs."""
        content_blocks = soup.select('div[data-component="text-block"] p, div.story-body__inner p, article div[data-component="text-block"] p, div.ssrcss-1q0x1qg-Paragraph.eq5iqo00')
        return '\n\n'.join(p.get_text(strip=True) for p in content_blocks if p.get_text(strip=True))

    def _extract_images(self, soup):
        """Extract the highest resolution image URL, prioritizing WebP. If no WebP, get the first highest resolution image."""
        
        highest_res_webp_url = None
        highest_res_other_url = None

        for img in soup.find_all('img', srcset=True):
            try:
                srcset_entries = [entry.strip().split() for entry in img['srcset'].split(',') if entry.strip()]
                if not srcset_entries:
                    continue

                largest_candidate = max(
                    srcset_entries,
                    key=lambda x: int(re.search(r'(\d+)w', x[1]).group(1)) if len(x) == 2 and re.search(r'(\d+)w', x[1]) else 0
                )
                current_image_url = urljoin(self.base_url, largest_candidate[0])

                if current_image_url.endswith('.webp'):
                    if not highest_res_webp_url:
                        highest_res_webp_url = current_image_url
                elif not highest_res_other_url:
                    highest_res_other_url = current_image_url

            except Exception as e:
                continue
        
        if highest_res_webp_url:
            return highest_res_webp_url
        elif highest_res_other_url:
            return highest_res_other_url
        
        main_img_element = soup.find('img', class_='ssrcss-1mj940c-Image e1gacx6g0') or \
                           soup.find('img', class_='qa-story-image') or \
                           soup.find('img', class_='js-image-replace') or \
                           soup.find('img')

        if main_img_element:
            direct_src_url = main_img_element.get('src') or main_img_element.get('data-src')
            if direct_src_url:
                if direct_src_url.endswith('.webp'):
                    return urljoin(self.base_url, direct_src_url)
                return urljoin(self.base_url, direct_src_url)

        return None

    def parse_article(self, article_url, category_url=None, category=None):
        """Parse a full article page and return structured data."""
        if article_url in self.visited_urls:
            print(f"Already visited {article_url}. Skipping.")
            return None

        self.visited_urls.add(article_url)
        html = self.get_page(article_url)
        if not html:
            print(f"Failed to get page for {article_url}. Skipping parsing.")
            return None

        soup = BeautifulSoup(html, 'html.parser')

        title = self._extract_title(soup)
        if not title:
            print(f"No title found for {article_url}")
            return None

        published_at = self._extract_timestamp(soup)
        author = self._extract_author(soup)
        extracted_category = self._extract_category_from_url(article_url)
        final_category = category or extracted_category
        
        # Get the approved tag from the category URL
        approved_tag = self._get_tag_from_url(category_url) if category_url else None
        tags = [approved_tag] if approved_tag else []
        print(f"[DEBUG] Using approved tag: {tags} (from category URL: {category_url})")

        content = self._extract_content(soup)
        image_url = self._extract_images(soup)

        summary_tag = soup.find('p', class_='ssrcss-1q0x1qg-Paragraph eq5iqo00') or \
                    soup.find('p', class_='qa-story-summary') or \
                    soup.find('p', class_='story-body__introduction')
        summary = summary_tag.get_text(strip=True) if summary_tag else (content[:200] + '...' if content and len(content) > 200 else content)

        word_count = len(content.split()) if content else 0
        words_per_minute = 200
        time_to_read = f"{max(1, round(word_count / words_per_minute))} min read" if word_count > 0 else "N/A"

        article_data = {
            'url': article_url,
            'title': title,
            'summary': summary,
            'content': content,
            'category': final_category,
            'source': 'BBC News',
            'image_url': image_url,
            'time_to_read': time_to_read,
            'published_at': published_at,
            'scraped_at': datetime.utcnow(),
            'author': author,
            'tags': tags
        }
        print(f"Successfully parsed article: {title} from {article_url}")
        return article_data

    def scrape_category_and_save(self, category_url, max_articles=10):
        """Scrape articles from a category and save them to the database."""
        scraped_links = self.extract_category_links(category_url, max_pages=1)
        
        saved_count = 0
        for link in scraped_links[:max_articles]:
            print(f"Attempting to parse and save: {link}")
            article_data = self.parse_article(
                link, 
                category_url=category_url,  # Pass the category URL here
                category=self._extract_category_from_url(link)
            )
            
            if not article_data or not article_data['title']:
                print(f"Skipping article due to missing data or title after parsing: {link}")
                continue

            existing_article = Article.query.filter_by(
                title=article_data['title'],
                source=article_data['source']
            ).first()

            if not existing_article:
                # Convert tags list to comma-separated string for database storage
                tags_str = ','.join(article_data['tags']) if article_data['tags'] else None

                new_article = Article(
                    title=article_data['title'],
                    summary=article_data['summary'],
                    content=article_data['content'],
                    category=article_data['category'],
                    source=article_data['source'],
                    image_url=article_data['image_url'],
                    time_to_read=article_data['time_to_read'],
                    published_at=article_data['published_at'],
                    scraped_at=article_data['scraped_at'],
                    author=article_data['author'],
                    tags=tags_str
                )
                db.session.add(new_article)
                saved_count += 1
                print(f"Added new article to DB: {new_article.title} with tags: {tags_str}")
            else:
                print(f"Article '{article_data['title']}' already exists in DB. Skipping.")
        
        db.session.commit()
        return saved_count

# --- Scheduled Scraping Function ---

def scheduled_scrape_news():
    """
    Function to be run by the scheduler to scrape news from various categories.
    This function must be run within an application context to access the database.
    """
    with app.app_context():
        print(f"[{datetime.now()}] Starting scheduled news scraping...")
        scraper = BBCNewsScraper()
        
        categories_to_scrape = {
            'Technology': 'https://www.bbc.com/news/technology',
            'Politics': 'https://www.bbc.com/news/politics',
            'Science': 'https://www.bbc.com/news/science_and_environment',
            'Business': 'https://www.bbc.com/news/business',
            'Entertainment': 'https://www.bbc.com/news/entertainment_and_arts',
            'Sport': 'https://www.bbc.com/sport',
        }
        
        total_new_articles_saved = 0
        
        for category_name, url in categories_to_scrape.items():
            try:
                print(f"[{datetime.now()}] Scraping category: {category_name} from {url}")
                saved_count = scraper.scrape_category_and_save(url, max_articles=5) 
                total_new_articles_saved += saved_count
                print(f"[{datetime.now()}] Finished scraping {category_name}. Saved {saved_count} new articles.")
            except Exception as e:
                print(f"[{datetime.now()}] Error scraping {category_name}: {e}")
                import traceback
                traceback.print_exc()
        
        print(f"[{datetime.now()}] Scheduled scraping finished. Total new articles saved: {total_new_articles_saved}")

# --- Routes ---

@app.route('/')
def home():
    """Renders the homepage (index.html). Accessible to all users."""
    return render_template('index.html')

@app.route('/article/<int:article_id>')
def article_detail(article_id):
    """Renders a single article's detailed view with a 3-paragraph preview made from all lines."""
    article = Article.query.get_or_404(article_id)
    
    content = article.content or ""
    lines = [line.strip() for line in content.split('\n') if line.strip()]  # clean empty lines
    
    n = len(lines)
    part_size = n // 3 if n >= 3 else n  # handle case with fewer than 3 lines
    
    paragraphs = [
        "\n".join(lines[0:part_size]),
        "\n".join(lines[part_size:2*part_size]),
        "\n".join(lines[2*part_size:]) if n > 2*part_size else ""
    ]
    
    # Filter out empty paragraphs (in case of few lines)
    paragraphs = [p for p in paragraphs if p]
    
    article.preview_content = '\n\n'.join(paragraphs)
    
    return render_template('article_detail.html', article=article)



@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles user registration."""
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role', 'user')

        if not username or not password:
            flash('Username and password are required!', 'error')
            return render_template('register.html')

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'error')
            return render_template('register.html')

        new_user = User(username=username, role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('home'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'error')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """Logs out the current user."""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/analytics')
@login_required
def analytics():
    """Renders the analytics page."""
    return render_template('analytics.html')

@app.route('/saved')
@login_required
def saved():
    """Renders the saved articles page."""
    return render_template('saved.html')

@app.route('/settings')
@login_required
def settings():
    """Renders the settings page."""
    return render_template('settings.html')

# --- API Endpoints for Frontend (e.g., index.html to fetch articles) ---

@app.route('/api/articles')
def get_articles():
    """API endpoint to fetch articles for the homepage."""
    articles = Article.query.order_by(Article.published_at.desc()).all()
    return jsonify([article.to_dict() for article in articles])

# --- Admin Panel Routes ---

@app.route('/admin')
@admin_required
def admin_dashboard():
    """Admin dashboard."""
    return render_template('admin/dashboard.html')

@app.route('/admin/users')
@admin_required
def admin_users():
    """Admin panel to manage users."""
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    """Admin panel to delete a user."""
    user_to_delete = User.query.get_or_404(user_id)
    if user_to_delete.role == 'admin' and user_to_delete.id != current_user.id:
        flash('Cannot delete another admin account.', 'error')
        return redirect(url_for('admin_users'))
    if user_to_delete.id == current_user.id:
        flash('You cannot delete your own account from here. Please logout first.', 'error')
        return redirect(url_for('admin_users'))

    db.session.delete(user_to_delete)
    db.session.commit()
    flash(f'User "{user_to_delete.username}" deleted successfully.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/toggle_admin/<int:user_id>', methods=['POST'])
@admin_required
def admin_toggle_admin(user_id):
    """Admin panel to toggle admin status of a user."""
    user_to_toggle = User.query.get_or_404(user_id)
    if user_to_toggle.id == current_user.id:
        flash('You cannot change your own admin status from here.', 'error')
        return redirect(url_for('admin_users'))

    if user_to_toggle.role == 'admin':
        user_to_toggle.role = 'user'
        flash(f'User "{user_to_toggle.username}" is no longer an admin.', 'info')
    else:
        user_to_toggle.role = 'admin'
        flash(f'User "{user_to_toggle.username}" is now an admin.', 'success')
    db.session.commit()
    return redirect(url_for('admin_users'))


@app.route('/admin/articles')
@admin_required
def admin_articles():
    """Admin panel to manage news articles."""
    articles = Article.query.order_by(Article.scraped_at.desc()).all()
    return render_template('admin/articles.html', articles=articles)

@app.route('/admin/articles/delete/<int:article_id>', methods=['POST'])
@admin_required
def admin_delete_article(article_id):
    """Admin panel to delete an article."""
    article_to_delete = Article.query.get_or_404(article_id)
    db.session.delete(article_to_delete)
    db.session.commit()
    flash(f'Article "{article_to_delete.title}" deleted successfully.', 'success')
    return redirect(url_for('admin_articles'))

@app.route('/admin/scrape', methods=['GET', 'POST'])
@admin_required
def admin_scrape_news():
    """Admin panel to trigger news scraping."""
    if request.method == 'POST':
        category_url = request.form.get('category_url')
        max_articles = int(request.form.get('max_articles', 10))
        
        if not category_url:
            flash('Category URL is required!', 'error')
            return render_template('admin/scrape_news.html')

        scraper = BBCNewsScraper() 
        try:
            saved_count = scraper.scrape_category_and_save(category_url, max_articles=max_articles)
            flash(f'Successfully scraped and saved {saved_count} new articles from {category_url}.', 'success')
        except Exception as e:
            flash(f'Error during scraping: {e}', 'error')
            import traceback
            traceback.print_exc()
        return redirect(url_for('admin_articles'))
    return render_template('admin/scrape_news.html')

# Run the Flask app
if __name__ == '__main__':
    import sys

    with app.app_context():
        db.create_all()

        # Ensure admin exists
        if not User.query.filter_by(username='admin').first():
            admin_user = User(username='admin', role='admin')
            admin_user.set_password('adminpass')
            db.session.add(admin_user)
            db.session.commit()
            print("Created default admin user: username='admin', password='adminpass'")

        # --- Run scraper if --scrape-now argument is passed ---
        if '--scrape' in sys.argv:
            print("[FORCE] Running immediate scrape...")
            scheduled_scrape_news()
            print("[FORCE] Scrape completed.")
            sys.exit(0)  # Exit after scraping

    # Normal scheduled jobs setup
    scheduler.start()
    with app.app_context():
        initial_run_date = datetime.now() - timedelta(seconds=1)
        scheduler.add_job(id='initial_scrape', func=scheduled_scrape_news, trigger='date', run_date=initial_run_date)
        scheduler.add_job(id='hourly_scrape', func=scheduled_scrape_news, trigger='interval', hours=1)
        print("Scheduled initial scrape and hourly scrape jobs.")

    app.run(debug=True)