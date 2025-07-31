# app.py
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
import requests
from bs4 import BeautifulSoup
import time
import json
from urllib.parse import urljoin, urlparse
import re
from functools import wraps
import random
from collections import defaultdict
import sys
from itsdangerous import URLSafeTimedSerializer
from flask import current_app

# Import Flask-APScheduler
from flask_apscheduler import APScheduler
from flask_mail import Mail, Message
from models import db, User, Article, SavedArticle, ReadingActivity, VerificationCode
from nlp_summarizer import summarize_new_articles

# Initialize Flask app
app = Flask(__name__)

# --- Configuration ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_super_secret_key_here')

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'frahaman832@gmail.com'
app.config['MAIL_PASSWORD'] = 'apxv ntmu neic ffdb'
app.config['MAIL_DEFAULT_SENDER'] = ('IntelliNews Team', 'frahaman832@gmail.com')

# Scheduler configuration
app.config['SCHEDULER_API_ENABLED'] = True

# --- Initialize extensions ---
db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)
scheduler = APScheduler()

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

def generate_verification_code():
    """Generate a 6-digit verification code"""
    return ''.join([str(random.randint(0, 9)) for _ in range(6)])

def send_verification_email(email, code):
    """Send verification email with the code"""
    msg = Message(
        'Your IntelliNews Verification Code',
        recipients=[email]
    )
    msg.body = f'Your verification code is: {code}\n\nThis code will expire in 10 minutes.'
    mail.send(msg)


# --- Recommendation System ---
class HybridRecommender:
    def __init__(self, db):
        self.db = db
    
    def get_recommendations(self, user_id, num_recommendations=5):
        """Get hybrid recommendations for a user"""
        # Get user's reading history
        user_activities = ReadingActivity.query.filter_by(user_id=user_id).all()
        
        if not user_activities:
            # If no history, return popular articles
            return self._get_popular_articles(num_recommendations)
        
        # Behavioral recommendations (based on reading history)
        behavioral_recs = self._get_behavioral_recommendations(user_id, num_recommendations)
        
        # Content-based recommendations (based on tags/categories)
        content_recs = self._get_content_recommendations(user_id, num_recommendations)
        
        # Combine and deduplicate recommendations
        combined = behavioral_recs + content_recs
        unique_recs = list({rec.id: rec for rec in combined}.values())
        
        # Remove already saved articles
        saved_ids = {sa.article_id for sa in SavedArticle.query.filter_by(user_id=user_id).all()}
        filtered_recs = [rec for rec in unique_recs if rec.id not in saved_ids]
        
        # Sort by relevance score (simple hybrid approach)
        return sorted(filtered_recs, key=lambda x: self._calculate_relevance_score(x, user_id), reverse=True)[:num_recommendations]
    
    def _get_behavioral_recommendations(self, user_id, num_recommendations):
        """Get recommendations based on user's reading patterns"""
        # Get most read tags by this user
        user_tags = db.session.query(
            ReadingActivity.tags,
            db.func.sum(ReadingActivity.time_spent).label('total_time')
        ).filter_by(user_id=user_id)\
         .group_by(ReadingActivity.tags)\
         .order_by(db.desc('total_time'))\
         .limit(3)\
         .all()
        
        if not user_tags:
            return []
        
        # Get articles with same tags that user hasn't read
        # Get articles with same tags that user hasn't read
        top_tags = [tag[0] for tag in user_tags]

        query = (
            Article.query
            .filter(Article.tags.in_(top_tags))
            .filter(~Article.reading_activities.any(user_id=user_id))
            .order_by(Article.published_at.desc())
            .limit(num_recommendations * 2)  # Get extra to filter later
        )

        
        return query.all()
    
    def _get_content_recommendations(self, user_id, num_recommendations):
        """Get recommendations based on article content similarity"""
        # Get user's most recent read articles
        recent_reads = (
                ReadingActivity.query
                .filter_by(user_id=user_id)
                .order_by(ReadingActivity.recorded_at.desc())
                .limit(3)
                .all()
            )
        
        if not recent_reads:
            return []
        
        # Get articles with similar tags to recently read articles
        recent_article_ids = [ra.article_id for ra in recent_reads]
        recent_articles = Article.query.filter(Article.id.in_(recent_article_ids)).all()
        
        if not recent_articles:
            return []
        
        # Collect tags from recent articles
        recent_tags = set()
        for article in recent_articles:
            if article.tags:
                recent_tags.update(article.tags.split(','))
        
        # Find articles with matching tags
        query = (
                Article.query
                .filter(Article.tags.in_(list(recent_tags)))
                .filter(~Article.id.in_(recent_article_ids))
                .order_by(Article.published_at.desc())
                .limit(num_recommendations * 2)  # Get extra to filter later
            )

        
        return query.all()
    
    def _get_popular_articles(self, num_recommendations):
        """Fallback to popular articles when no user history exists"""
        return Article.query.order_by(Article.published_at.desc()).limit(num_recommendations).all()
    
    def _calculate_relevance_score(self, article, user_id):
        """Simple relevance scoring combining behavioral and content signals"""
        score = 0
        
        # Behavioral component - time spent on similar tags
        user_tags = db.session.query(
            ReadingActivity.tags,
            db.func.sum(ReadingActivity.time_spent).label('total_time')
        ).filter_by(user_id=user_id)\
         .group_by(ReadingActivity.tags)\
         .all()
        
        if article.tags and user_tags:
            article_tags = set(article.tags.split(','))
            for tag, time in user_tags:
                if tag in article_tags:
                    score += time / 60  # Convert seconds to minutes
        
        # Content component - recency boost
        days_old = (datetime.utcnow() - article.published_at).days if article.published_at else 30
        recency_boost = max(0, 1 - (days_old / 30))  # Linear decay over 30 days
        score += recency_boost * 10  # Recency can add up to 10 points
        
        return score

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

    def _generate_summary(self, content, max_sentences=3):
        """Generate a proper summary from the content by selecting key sentences."""
        if not content:
            return ""
    
        summary = "Loading Soon ..."
        
        return summary




        

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

        summary = self._generate_summary(content) if content else None

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
            'Science': 'https://www.bbc.com/innovation',
            'Business': 'https://www.bbc.com/news/business',
            'Entertainment': 'https://www.bbc.com/news/entertainment_and_arts',
            'Sport': 'https://www.bbc.com/sport/cricket',
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

def initialize_database():
    """Initialize the database with default data if empty."""
    with app.app_context():
        # Create all database tables
        db.create_all()
        
        # Check if we have any articles
        if db.session.query(db.Model.metadata.tables['article']).count() == 0:
            print("No articles found in database. Running initial scrape...")
            scheduled_scrape_news()
            summarize_new_articles(app, db, Article)
        
        # Ensure admin exists
        if not User.query.filter_by(username='admin').first():
            admin_user = User(
                username='admin',
                email='admin@intellinews.com',  # Add email field
                role='admin'
            )
            admin_user.set_password('adminpass')
            db.session.add(admin_user)
            db.session.commit()
            print("Created default admin user: username='admin', email='admin@intellinews.com', password='adminpass'")

def register_scheduler():
    scheduler.init_app(app)
    scheduler.start()
    
    # Add jobs with proper app context handling
    scheduler.add_job(
        id='scrape_news',
        func=run_scrape_with_context,
        trigger='interval',
        minutes=15
    )
    
    scheduler.add_job(
        id='summarize_articles',
        func=run_summarize_with_context,
        trigger='interval',
        minutes=10
    )

def run_scrape_with_context():
    with app.app_context():
        print(f"\n [Scrape Job Started at {datetime.now()}]")
        scheduled_scrape_news()
        print(f" [Scrape Job Completed at {datetime.now()}]\n")

def run_summarize_with_context():
    with app.app_context():
        print(f"\n [Summarize Job Started at {datetime.now()}]")
        summarize_new_articles(app, db, Article)
        print(f" [Summarize Job Completed at {datetime.now()}]\n")


# Add this after the mail initialization
def generate_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='password-reset-salt')

def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt='password-reset-salt',
            max_age=expiration
        )
    except:
        return False
    return email

# Add these new routes after the existing routes
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """Handle password reset requests"""
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()

        if not user:
            flash('If an account exists with this email, a reset link has been sent.', 'info')
            return redirect(url_for('login'))

        # Generate verification code
        code = generate_verification_code()
        
        # Delete any existing verification for this email
        VerificationCode.query.filter_by(email=email).delete()
        
        # Create new verification record
        verification = VerificationCode(email=email, code=code)
        db.session.add(verification)
        db.session.commit()

        try:
            send_verification_email(email, code)
            flash('Verification code sent to your email. Please check your inbox.', 'success')
            return render_template('reset_password_request.html', email=email, show_verification=True)
        except Exception as e:
            db.session.rollback()
            flash('Failed to send verification email. Please try again.', 'error')
            return render_template('reset_password_request.html')

    return render_template('reset_password_request.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    """Handle password reset with verification code"""
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        email = request.form.get('email')
        verification_code = request.form.get('verification_code')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Verify the code first
        verification = VerificationCode.query.filter_by(email=email).first()
        
        if not verification:
            flash('No verification request found for this email. Please start over.', 'error')
            return redirect(url_for('forgot_password'))
        
        if verification.code != verification_code:
            flash('Invalid verification code. Please try again.', 'error')
            return render_template('reset_password_request.html', 
                                 email=email,
                                 show_verification=True)
        
        if verification.expires_at < datetime.utcnow():
            flash('Verification code has expired. Please request a new one.', 'error')
            return render_template('reset_password_request.html', 
                                 email=email,
                                 show_verification=True)

        # Now verify passwords match
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('reset_password_request.html',
                                email=email,
                                show_verification=True)

        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'error')
            return render_template('reset_password_request.html',
                                email=email,
                                show_verification=True)

        # Find user and update password
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('No account found with this email.', 'error')
            return redirect(url_for('forgot_password'))

        user.set_password(password)
        
        # Clean up verification code
        db.session.delete(verification)
        db.session.commit()

        flash('Your password has been updated! You can now log in.', 'success')
        return redirect(url_for('login'))

    return redirect(url_for('forgot_password'))

# --- Routes ---
@app.route('/')
def home():
    """Renders the homepage (index.html). Accessible to all users."""
    return render_template('index.html')

@app.route('/article/<int:article_id>')
def article_detail(article_id):
    """Renders a single article's detailed view with a 3-paragraph preview made from all lines."""
    article = Article.query.get_or_404(article_id)
    
    # Record initial reading activity (10 seconds by default)
    if current_user.is_authenticated:
        # Get the first tag or default to 'General'
        tag = article.tags.split(',')[0] if article.tags else 'General'
        
        reading_activity = ReadingActivity(
            user_id=current_user.id,
            article_id=article_id,
            time_spent=10,  # Default 10 seconds for clicking
            tags=tag,
            date=datetime.utcnow().date(),
            recorded_at=datetime.utcnow()
        )
        db.session.add(reading_activity)
        db.session.commit()
    
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
    """Handles user registration with email verification."""
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        # Step 1: Verify email with code
        if 'verification_code' in request.form:
            email = request.form.get('email')
            username = request.form.get('username')
            password = request.form.get('password')
            verification_code = request.form.get('verification_code')
            
            verification = VerificationCode.query.filter_by(email=email).first()
            
            if not verification:
                flash('No verification request found for this email. Please start over.', 'error')
                return redirect(url_for('register'))
            
            if verification.code != verification_code:
                flash('Invalid verification code. Please try again.', 'error')
                return render_template('register.html', 
                                    email=email,
                                    username=username,
                                    password=password,
                                    show_verification=True)
            
            if verification.expires_at < datetime.utcnow():
                flash('Verification code has expired. Please request a new one.', 'error')
                return render_template('register.html', 
                                    email=email,
                                    username=username,
                                    password=password,
                                    show_verification=True)
            
            # Check if username or email already exists
            if User.query.filter_by(username=username).first():
                flash('Username already exists. Please choose a different one.', 'error')
                return render_template('register.html', 
                                    email=email,
                                    password=password,
                                    show_verification=True)
            
            if User.query.filter_by(email=email).first():
                flash('Email already registered. Please use a different email.', 'error')
                return render_template('register.html',
                                    username=username,
                                    password=password,
                                    show_verification=True)
            
            # Create new user with email
            new_user = User(
                username=username,
                email=email,  # This is the critical fix
                role='user'
            )
            new_user.set_password(password)
            db.session.add(new_user)
            
            # Clean up verification code
            db.session.delete(verification)
            db.session.commit()
            
            flash('Account created successfully! You can now log in.', 'success')
            return redirect(url_for('login'))
        
        # Step 2: Send verification code
        else:
            email = request.form.get('email')
            username = request.form.get('username')
            password = request.form.get('password')
            
            if not all([email, username, password]):
                flash('All fields are required!', 'error')
                return render_template('register.html')
            
            # Check if username or email exists
            if User.query.filter_by(username=username).first():
                flash('Username already exists. Please choose a different one.', 'error')
                return render_template('register.html')
            
            if User.query.filter_by(email=email).first():
                flash('Email already registered. Please use a different email.', 'error')
                return render_template('register.html')
            
            # Generate and send verification code
            code = generate_verification_code()
            
            # Delete any existing verification for this email
            VerificationCode.query.filter_by(email=email).delete()
            
            # Create new verification record
            verification = VerificationCode(email=email, code=code)
            db.session.add(verification)
            db.session.commit()
            
            try:
                send_verification_email(email, code)
                flash('Verification code sent to your email. Please check your inbox.', 'success')
                return render_template('register.html', 
                                    email=email,
                                    username=username,
                                    password=password,
                                    show_verification=True)
            except Exception as e:
                db.session.rollback()
                flash('Failed to send verification email. Please try again.', 'error')
                return render_template('register.html')

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
    saved_articles = SavedArticle.query.filter_by(user_id=current_user.id).order_by(SavedArticle.saved_at.desc()).all()
    return render_template('saved.html', saved_articles=saved_articles)

@app.route('/save_article/<int:article_id>', methods=['POST'])
@login_required
def save_article(article_id):
    """Saves an article for the current user."""
    article = Article.query.get_or_404(article_id)
    
    # Check if already saved
    existing_save = SavedArticle.query.filter_by(
        user_id=current_user.id,
        article_id=article_id
    ).first()
    
    if existing_save:
        return jsonify({'status': 'already_saved'})
    
    saved_article = SavedArticle(
        user_id=current_user.id,
        article_id=article_id,
        saved_at=datetime.utcnow()
    )
    db.session.add(saved_article)
    db.session.commit()
    
    return jsonify({'status': 'success'})

@app.route('/unsave_article/<int:article_id>', methods=['POST'])
@login_required
def unsave_article(article_id):
    """Removes an article from the current user's saved articles."""
    saved_article = SavedArticle.query.filter_by(
        user_id=current_user.id,
        article_id=article_id
    ).first_or_404()
    
    db.session.delete(saved_article)
    db.session.commit()
    
    return jsonify({'status': 'success'})

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

@app.route('/api/recommendations')
@login_required
def get_recommendations():
    """Get personalized article recommendations for the current user"""
    recommender = HybridRecommender(db)
    recommendations = recommender.get_recommendations(current_user.id, num_recommendations=5)
    return jsonify([article.to_dict() for article in recommendations])

    
@app.route('/api/user_analytics')
@login_required
def user_analytics():
    """Simplified analytics endpoint showing tag distribution and daily reading time"""
    # Get all reading activities for the current user
    activities = ReadingActivity.query.filter_by(
        user_id=current_user.id
    ).order_by(
        ReadingActivity.date.desc()
    ).all()

    # Prepare data for charts
    tag_distribution = defaultdict(int)
    daily_reading = defaultdict(int)
    
    for activity in activities:
        # Calculate reading time in minutes
        minutes = activity.time_spent / 60
        
        # Update tag distribution
        if activity.tags:
            tag_distribution[activity.tags] += minutes
        
        # Update daily reading time
        date_str = activity.date.strftime('%Y-%m-%d')
        daily_reading[date_str] += minutes

    # Convert to lists for charting
    tags = list(tag_distribution.keys())
    tag_minutes = list(tag_distribution.values())
    
    dates = sorted(daily_reading.keys())
    daily_minutes = [daily_reading[date] for date in dates]

    return jsonify({
        'tags': tags,
        'tag_minutes': tag_minutes,
        'dates': dates,
        'daily_minutes': daily_minutes
    })

@app.route('/api/record_reading_activity', methods=['POST'])
@login_required
def record_reading_activity():
    data = request.get_json()
    article_id = data.get('article_id')
    time_spent = data.get('time_spent', 0)
    
    article = Article.query.get_or_404(article_id)
    
    # Get the first tag or default to 'General'
    tag = article.tags.split(',')[0] if article.tags else 'General'
    
    # Get existing activity for today or create new
    today = datetime.utcnow().date()
    activity = ReadingActivity.query.filter_by(
        user_id=current_user.id,
        article_id=article_id,
        date=today
    ).first()
    
    if activity:
        # Update existing record
        activity.time_spent += time_spent
    else:
        # Create new record
        activity = ReadingActivity(
            user_id=current_user.id,
            article_id=article_id,
            time_spent=time_spent,
            date=today,
            tags=tag,
            recorded_at=datetime.utcnow()
        )
        db.session.add(activity)
    
    db.session.commit()
    return jsonify({'status': 'success'})


@app.route('/api/change_password', methods=['POST'])
@login_required
def change_password():
    """Change the user's password after verifying current password."""
    data = request.get_json()
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    
    if not current_password or not new_password:
        return jsonify({'message': 'Current password and new password are required'}), 400
    
    if len(new_password) < 8:
        return jsonify({'message': 'New password must be at least 8 characters long'}), 400
    
    # Verify current password
    if not current_user.check_password(current_password):
        return jsonify({'message': 'Current password is incorrect'}), 401
    
    # Set new password
    current_user.set_password(new_password)
    db.session.commit()
    
    return jsonify({'message': 'Password changed successfully'}), 200

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

    # First delete all associated reading activities
    ReadingActivity.query.filter_by(user_id=user_id).delete()
    
    # Then delete all saved articles
    SavedArticle.query.filter_by(user_id=user_id).delete()
    
    # Finally delete the user
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
    """Admin panel to delete an article and all its references."""
    article_to_delete = Article.query.get_or_404(article_id)
    
    try:
        # First delete all SavedArticle records that reference this article
        SavedArticle.query.filter_by(article_id=article_id).delete()
        
        # Then delete all ReadingActivity records that reference this article
        ReadingActivity.query.filter_by(article_id=article_id).delete()
        
        # Finally delete the article itself
        db.session.delete(article_to_delete)
        db.session.commit()
        
        flash(f'Article "{article_to_delete.title}" and all its references deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting article: {str(e)}', 'error')
        app.logger.error(f"Error deleting article {article_id}: {str(e)}")
    
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

if __name__ == '__main__':
    # Initialize database first
    initialize_database()
    
    # Register and start scheduler
    register_scheduler()
    
    try:
        app.run(debug=True)
    except (KeyboardInterrupt, SystemExit):
        # Proper shutdown
        scheduler.shutdown()
        raise