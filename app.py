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
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
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
db = SQLAlchemy(app)  
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)
scheduler = APScheduler()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(10), default='user', nullable=False)
    saved_articles = db.relationship('SavedArticle', backref='user', lazy=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    preferred_categories = db.Column(db.String(255), nullable=True)  # Comma-separated list
    reading_time_preference = db.Column(db.String(20), nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

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
    tags = db.Column(db.String(255), nullable=True)
    saved_by_users = db.relationship('SavedArticle', backref='article', cascade='all, delete-orphan', lazy=True)

    def to_dict(self):
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
            'tags': self.tags.split(',') if self.tags else []
        }

class SavedArticle(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    article_id = db.Column(db.Integer, db.ForeignKey('article.id', ondelete='CASCADE'), nullable=False)
    saved_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    __table_args__ = (db.UniqueConstraint('user_id', 'article_id', name='unique_user_article'),)

class ReadingActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    article_id = db.Column(db.Integer, db.ForeignKey('article.id'), nullable=False)
    time_spent = db.Column(db.Integer, nullable=False)
    date = db.Column(db.Date, nullable=False, index=True)
    tags = db.Column(db.String(50), nullable=True)
    recorded_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='reading_activities')
    article = db.relationship('Article', backref='reading_activities')

class VerificationCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    code = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    
    def __init__(self, email, code):
        self.email = email
        self.code = code
        self.expires_at = datetime.utcnow() + timedelta(minutes=10)

class RecommendationEvaluation(db.Model):
    """Tracks recommendation impressions and clicks"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    article_id = db.Column(db.Integer, db.ForeignKey('article.id'))
    shown_at = db.Column(db.DateTime, default=datetime.utcnow)
    clicked = db.Column(db.Boolean, default=False)
    clicked_at = db.Column(db.DateTime)
    saved = db.Column(db.Boolean, default=False)
    recommendation_strategy = db.Column(db.String(50))  # 'hybrid', 'popular', 'random'
    
    user = db.relationship('User', backref='recommendation_evals')
    article = db.relationship('Article', backref='recommendation_evals')

class EvaluationBaseline(db.Model):
    """Stores daily metrics for comparison"""
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, unique=True)
    hybrid_impressions = db.Column(db.Integer)
    hybrid_clicks = db.Column(db.Integer)
    popular_impressions = db.Column(db.Integer)
    popular_clicks = db.Column(db.Integer)
    random_impressions = db.Column(db.Integer)
    random_clicks = db.Column(db.Integer)
    hybrid_saves = db.Column(db.Integer)
    popular_saves = db.Column(db.Integer)
    random_saves = db.Column(db.Integer)


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
    
    def get_recommendations(self, user_id, num_recommendations=None):
        """Get hybrid recommendations for a user"""
        # Calculate 10% of total articles if num_recommendations isn't specified
        if num_recommendations is None:
            total_articles = Article.query.count()
            num_recommendations = max(1, int(total_articles * 0.1))  # Ensure at least 1 recommendation

        # Get user's reading history
        user = User.query.get(user_id)
        user_activities = ReadingActivity.query.filter_by(user_id=user_id).all()
        
        # Get preferences
        preferred_categories = []
        if user.preferred_categories:
            preferred_categories = user.preferred_categories.split(',')
        
        # If no history but has preferences, use those
        if not user_activities and preferred_categories:
            return self._get_articles_by_categories(preferred_categories, num_recommendations)
        
        if not user_activities:
            # If no history, return popular articles (10% of total)
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
        
    def _get_articles_by_categories(self, categories, limit):
        return Article.query.filter(
            Article.tags.in_(categories)
        ).order_by(
            Article.published_at.desc()
        ).limit(limit).all()

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

class MultiNewsScraper:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept-Language': 'en-US,en;q=0.5'
        })
        self.rate_limit_delay = 1.0  # seconds between requests
        self.visited_urls = set()

    def get_page(self, url):
        """Fetch a page with error handling."""
        try:
            time.sleep(self.rate_limit_delay)
            response = self.session.get(url)
            response.raise_for_status()
            return response.text
        except requests.exceptions.RequestException as e:
            print(f"Error fetching {url}: {e}")
            return None

    def _extract_links(self, html, site):
        """Extract article links based on the news site."""
        soup = BeautifulSoup(html, 'html.parser')
        links = set()

        if site == 'bbc':
            for link in soup.select('a[data-testid="internal-link"], a.qa-heading-link, a.gs-c-promo-heading__link, a.ssrcss-ug1v3a-PromoLink'):
                href = link.get('href')
                if href and '/news/' in href:
                    full_url = urljoin('https://www.bbc.com', href)
                    if (re.match(r'.*/news/articles/[a-z0-9]+$', full_url) or
                        re.match(r'.*/news/[a-z0-9-]+-\d+$', full_url)) and \
                       'live' not in full_url.lower():
                        links.add(full_url)
        elif site == 'cnn':
            for link in soup.select('a.container__link'):
                href = link.get('href')
                if href and '/202' in href:
                    links.add(f"https://www.cnn.com{href}" if not href.startswith('http') else href)
        elif site == 'npr':
            for link in soup.select('h2.title > a[href*="/202"], a.title[href*="/202"]'):
                href = link.get('href')
                if href and '/202' in href:
                    links.add(href if href.startswith('http') else f"https://www.npr.org{href}")
        elif site == 'apnews':
            for link in soup.select('a[href*="/article/"]'):
                href = link.get('href')
                if href and '/article/' in href:
                    links.add(href if href.startswith('http') else f"https://apnews.com{href}")
        elif site == 'aljazeera':
            for link in soup.select('a.u-clickable-card__link'):
                href = link.get('href')
                if href and '/202' in href:
                    links.add(f"https://www.aljazeera.com{href}")

        return list(links)[:10]  # Return up to 10 articles per site

    def _generate_summary(self, content, max_sentences=3):
        """Generate a proper summary from the content by selecting key sentences."""
        if not content:
            return "Loading Soon ..."
        return "Loading Soon ..."  # Will be replaced by NLP summarizer

    def _get_tag_from_url(self, url):
        """Extract and return only the approved tag from the URL"""
        if not url:
            return 'General'
            
        url = url.lower()
        if 'technology' in url or 'tech' in url:
            return 'Technology'
        elif 'politics' in url:
            return 'Politics'
        elif 'science' in url or 'environment' in url or 'health' in url:
            return 'Science'
        elif 'business' in url or 'economy' in url or 'finance' in url:
            return 'Business'
        elif 'entertainment' in url or 'arts' in url or 'culture' in url:
            return 'Entertainment'
        elif 'sport' in url or 'sports' in url:
            return 'Sport'
        return 'General'

    def _extract_category_from_url(self, url):
        """Extract category name from URL."""
        path = urlparse(url).path
        parts = [p for p in path.split('/') if p]
        if len(parts) > 1:
            return parts[1].replace('-', ' ').title()
        return 'General'

    def _extract_article_data(self, url, html):
        """Parse article content based on the news site."""
        soup = BeautifulSoup(html, 'html.parser')
        domain = urlparse(url).netloc
        data = {'url': url}

        if 'bbc.com' in domain:
            data.update({
                'title': soup.find('h1', class_='sc-f98b1ad2-0 dfvxux').get_text(strip=True) if soup.find('h1', class_='sc-f98b1ad2-0 dfvxux') else None,
                'content': '\n\n'.join([p.get_text(strip=True) for p in soup.select('div[data-component="text-block"] p, div.story-body__inner p, article p, p.ssrcss-1q0x1qg-Paragraph')]),
                'author': soup.find('div', class_='ssrcss-68pt20-Text-TextContributorName').get_text(strip=True) if soup.find('div', class_='ssrcss-68pt20-Text-TextContributorName') else None,
                'published_at': soup.find('time')['datetime'] if soup.find('time') and 'datetime' in soup.find('time').attrs else None,
                'image_url': self._extract_images(soup),
                'source': 'BBC News'
            })
        elif 'cnn.com' in domain:
            data.update({
                'title': soup.find('h1').get_text(strip=True) if soup.find('h1') else None,
                'content': '\n\n'.join([p.get_text(strip=True) for p in soup.select('div.article__content p, section.article__content p, div.paragraph')]),
                'author': soup.find('span', class_='byline__name').get_text(strip=True) if soup.find('span', class_='byline__name') else None,
                'published_at': soup.find('div', class_='timestamp').get_text(strip=True) if soup.find('div', class_='timestamp') else None,
                'image_url': soup.find('img', class_='image__dam-img').get('src') if soup.find('img', class_='image__dam-img') else None,
                'source': 'CNN'
            })
        elif 'npr.org' in domain:
            data.update({
                'title': soup.find('h1').get_text(strip=True) if soup.find('h1') else None,
                'content': '\n\n'.join([p.get_text(strip=True) for p in soup.select('div.storytext p, article p, p.storytext')]),
                'author': soup.find('div', class_='byline__byline').get_text(strip=True) if soup.find('div', class_='byline__byline') else None,
                'published_at': soup.find('time')['datetime'] if soup.find('time') and 'datetime' in soup.find('time').attrs else None,
                'image_url': soup.find('img', class_='img')['src'] if soup.find('img', class_='img') else None,
                'source': 'NPR'
            })
        elif 'apnews.com' in domain:
            data.update({
                'title': soup.find('h1').get_text(strip=True) if soup.find('h1') else None,
                'content': '\n\n'.join([p.get_text(strip=True) for p in soup.select('div.Article p, div.RichTextStoryBody p, article p, p.Component-root')]),
                'author': soup.find('span', class_='Component-byline').get_text(strip=True) if soup.find('span', class_='Component-byline') else None,
                'published_at': soup.find('span', class_='Timestamp').get_text(strip=True) if soup.find('span', class_='Timestamp') else None,
                'image_url': soup.find('img', class_='Image')['src'] if soup.find('img', class_='Image') else None,
                'source': 'AP News'
            })
        elif 'aljazeera.com' in domain:
            data.update({
                'title': soup.find('h1').get_text(strip=True) if soup.find('h1') else None,
                'content': '\n\n'.join([p.get_text(strip=True) for p in soup.select('div.article__content p, div.wysiwyg p, article p, p.article__content')]),
                'author': soup.find('div', class_='article-author').get_text(strip=True) if soup.find('div', class_='article-author') else None,
                'published_at': soup.find('time')['datetime'] if soup.find('time') and 'datetime' in soup.find('time').attrs else None,
                'image_url': soup.find('img', class_='article-featured-image').get('src') if soup.find('img', class_='article-featured-image') else None,
                'source': 'Al Jazeera'
            })

        # Process common fields
        if data.get('published_at'):
            try:
                data['published_at'] = datetime.fromisoformat(data['published_at'].replace('Z', '+00:00'))
            except ValueError:
                try:
                    data['published_at'] = datetime.strptime(data['published_at'], '%Y-%m-%dT%H:%M:%S%z')
                except:
                    data['published_at'] = None

        # Get category and tags
        data['category'] = "Article"
        data['tags'] = [self._get_tag_from_url(url)]
        
        # Generate summary
        data['summary'] = self._generate_summary(data.get('content'))
        
        # Calculate time to read
        word_count = len(data.get('content', '').split())
        words_per_minute = 200
        data['time_to_read'] = f"{max(1, round(word_count / words_per_minute))} min read" if word_count > 0 else "N/A"
        
        return data

    def _extract_images(self, soup):
        """Extract the highest resolution image URL."""
        for img in soup.find_all('img', srcset=True):
            try:
                srcset_entries = [entry.strip().split() for entry in img['srcset'].split(',') if entry.strip()]
                if not srcset_entries:
                    continue

                largest_candidate = max(
                    srcset_entries,
                    key=lambda x: int(re.search(r'(\d+)w', x[1]).group(1)) if len(x) == 2 and re.search(r'(\d+)w', x[1]) else 0
                )
                image_url = largest_candidate[0]
                if image_url.startswith('http'):
                    return image_url
                return urljoin('https://' + urlparse(img['srcset']).netloc, image_url)
            except Exception as e:
                continue
        
        main_img = soup.find('img')
        if main_img and main_img.get('src'):
            return main_img.get('src')
        return None

    def scrape_and_save(self, site_url, max_articles=5):
        """Scrape articles from a site and save them to the database."""
        domain = urlparse(site_url).netloc
        site = None
        
        if 'bbc.com' in domain:
            site = 'bbc'
        elif 'cnn.com' in domain:
            site = 'cnn'
        elif 'npr.org' in domain:
            site = 'npr'
        elif 'apnews.com' in domain:
            site = 'apnews'
        elif 'aljazeera.com' in domain:
            site = 'aljazeera'
        else:
            print(f"Unsupported site: {site_url}")
            return 0

        html = self.get_page(site_url)
        if not html:
            print(f"Failed to fetch HTML for {site_url}")
            return 0

        article_links = self._extract_links(html, site)
        if not article_links:
            print(f"No article links found for {site_url}")
            return 0

        saved_count = 0
        for link in article_links[:max_articles]:
            if link in self.visited_urls:
                continue
                
            print(f"Attempting to parse and save: {link}")
            article_html = self.get_page(link)
            if not article_html:
                continue

            article_data = self._extract_article_data(link, article_html)
            
            # Skip if no content or no title
            if not article_data or not article_data.get('title') or not article_data.get('content'):
                print(f"Skipping article - missing title or content: {link}")
                continue

            # Skip if content is too short (less than 100 words)
            word_count = len(article_data.get('content', '').split())
            if word_count < 100:
                print(f"Skipping article - content too short ({word_count} words): {link}")
                continue

            existing_article = Article.query.filter_by(
                title=article_data['title'],
                source=article_data['source']
            ).first()

            if not existing_article:
                new_article = Article(
                    title=article_data['title'],
                    summary=article_data['summary'],
                    content=article_data['content'],
                    category=article_data['category'],
                    source=article_data['source'],
                    image_url=article_data['image_url'],
                    time_to_read=article_data['time_to_read'],
                    published_at=article_data['published_at'],
                    scraped_at=datetime.utcnow(),
                    author=article_data.get('author'),
                    tags=','.join(article_data['tags']) if article_data['tags'] else None
                )
                db.session.add(new_article)
                saved_count += 1
                print(f"Added new article to DB: {new_article.title}")
            else:
                print(f"Article '{article_data['title']}' already exists in DB. Skipping.")

            self.visited_urls.add(link)

        db.session.commit()
        return saved_count

# --- Scheduled Scraping Function ---
def scheduled_scrape_news():
    """
    Function to be run by the scheduler to scrape news from various sources.
    This function must be run within an application context to access the database.
    """
    with app.app_context():
        print(f"[{datetime.now()}] Starting scheduled news scraping...")
        scraper = MultiNewsScraper()
        
        sites_to_scrape = {
            'BBC': 'https://www.bbc.com/news',
            'CNN': 'https://www.cnn.com/world',
            'NPR': 'https://www.npr.org/sections/news/',
            'AP News': 'https://apnews.com/hub/world-news',
            'Al Jazeera': 'https://www.aljazeera.com/news/'
        }
        
        total_new_articles_saved = 0
        
        for name, url in sites_to_scrape.items():
            try:
                print(f"[{datetime.now()}] Scraping site: {name} from {url}")
                saved_count = scraper.scrape_and_save(url, max_articles=5)
                total_new_articles_saved += saved_count
                print(f"[{datetime.now()}] Finished scraping {name}. Saved {saved_count} new articles.")
            except Exception as e:
                print(f"[{datetime.now()}] Error scraping {name}: {e}")
                import traceback
                traceback.print_exc()
        
        print(f"[{datetime.now()}] Scheduled scraping finished. Total new articles saved: {total_new_articles_saved}")


def initialize_database():
    """Initialize the database with default data if empty."""
    with app.app_context():
        # Create all database tables
        db.create_all()
        
        # Check if we have any articles
        if Article.query.count() == 0:
            print("No articles found in database. Running initial scrape...")
            scheduled_scrape_news()
            summarize_new_articles(app, db, Article)
        
        # Ensure admin exists
        if not User.query.filter_by(username='admin').first():
            admin_user = User(
                username='admin',
                email='admin@intellinews.com',
                role='admin'
            )
            admin_user.set_password('adminpass')
            db.session.add(admin_user)
            db.session.commit()
            print("Created default admin user")

initialize_database()

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

    scheduler.add_job(
            id='calculate_daily_metrics',
            func=run_daily_metrics_with_context,
            trigger='interval',
            hours=2,
            start_date=datetime.now() + timedelta(minutes=1),
            replace_existing=True
        )

def run_daily_metrics_with_context():
    with app.app_context():
        calculate_daily_metrics()

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


def calculate_daily_metrics():
    """Calculates and stores daily metrics"""
    today = datetime.utcnow().date()
    
    # Check if already calculated today
    if EvaluationBaseline.query.filter_by(date=today).first():
        return
    
    # Hybrid metrics
    hybrid = db.session.query(
        db.func.count(RecommendationEvaluation.id),
        db.func.sum(db.case((RecommendationEvaluation.clicked == True, 1), else_=0)),
        db.func.sum(db.case((RecommendationEvaluation.saved == True, 1), else_=0))
    ).filter(
        db.func.date(RecommendationEvaluation.shown_at) == today,
        RecommendationEvaluation.recommendation_strategy == 'hybrid'
    ).first()
    
    # Popular metrics
    popular = db.session.query(
        db.func.count(RecommendationEvaluation.id),
        db.func.sum(db.case((RecommendationEvaluation.clicked == True, 1), else_=0)),
        db.func.sum(db.case((RecommendationEvaluation.saved == True, 1), else_=0))
    ).filter(
        db.func.date(RecommendationEvaluation.shown_at) == today,
        RecommendationEvaluation.recommendation_strategy == 'popular'
    ).first()
    
    # Random metrics
    random = db.session.query(
        db.func.count(RecommendationEvaluation.id),
        db.func.sum(db.case((RecommendationEvaluation.clicked == True, 1), else_=0)),
        db.func.sum(db.case((RecommendationEvaluation.saved == True, 1), else_=0))
    ).filter(
        db.func.date(RecommendationEvaluation.shown_at) == today,
        RecommendationEvaluation.recommendation_strategy == 'random'
    ).first()
    
    # Save to baseline table
    baseline = EvaluationBaseline(
        date=today,
        hybrid_impressions=hybrid[0] or 0,
        hybrid_clicks=hybrid[1] or 0,
        hybrid_saves=hybrid[2] or 0,
        popular_impressions=popular[0] or 0,
        popular_clicks=popular[1] or 0,
        popular_saves=popular[2] or 0,
        random_impressions=random[0] or 0,
        random_clicks=random[1] or 0,
        random_saves=random[2] or 0
    )
    db.session.add(baseline)
    db.session.commit()

        
# --- Routes ---
@app.route('/')
def home():
    """Renders the homepage (index.html). Accessible to all users."""
    return render_template('index.html')


@app.route('/admin/stats')
@admin_required
def admin_stats():
    """Admin panel to view system statistics."""
    # User statistics
    user_count = User.query.count()
    admin_count = User.query.filter_by(role='admin').count()
    regular_user_count = user_count - admin_count
    
    # Article statistics
    article_count = Article.query.count()
    
    # Articles from today
    today = datetime.utcnow().date()
    today_article_count = Article.query.filter(
        db.func.date(Article.scraped_at) == today
    ).count()
    
    # Articles from this week
    week_start = today - timedelta(days=today.weekday())
    week_article_count = Article.query.filter(
        Article.scraped_at >= week_start
    ).count()
    
    # Articles added in the last 7 days
    last_7_days = []
    for i in range(6, -1, -1):
        day = today - timedelta(days=i)
        count = Article.query.filter(
            db.func.date(Article.scraped_at) == day
        ).count()
        last_7_days.append((day.strftime('%Y-%m-%d'), count))
    
    # Category distribution
    categories = Article.query.with_entities(
        Article.tags, 
        db.func.count(Article.id)
    ).group_by(Article.tags).all()
    
    category_distribution = {}
    for category, count in categories:
        if category:
            # Extract the first tag as the category
            main_category = category.split(',')[0] if category else 'General'
            category_distribution[main_category] = category_distribution.get(main_category, 0) + count
        else:
            category_distribution['General'] = category_distribution.get('General', 0) + count
    
    # Source distribution
    sources = Article.query.with_entities(
        Article.source, 
        db.func.count(Article.id)
    ).group_by(Article.source).all()
    
    source_distribution = {source: count for source, count in sources if source}
    
    return render_template(
        'admin/stats.html',
        user_count=user_count,
        admin_count=admin_count,
        regular_user_count=regular_user_count,
        article_count=article_count,
        today_article_count=today_article_count,
        week_article_count=week_article_count,
        last_7_days=last_7_days,
        category_distribution=category_distribution,
        source_distribution=source_distribution
    )

@app.route('/api/save_preferences', methods=['POST'])
@login_required
def save_preferences():
    data = request.get_json()
    current_user.preferred_categories = ','.join(data.get('categories', []))
    current_user.reading_time_preference = data.get('readingTime')
    db.session.commit()
    return jsonify({'status': 'success'})

@app.route('/api/get_preferences')
@login_required
def get_preferences():
    return jsonify({
        'categories': current_user.preferred_categories.split(',') if current_user.preferred_categories else [],
        'readingTime': current_user.reading_time_preference
    })

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

# --- Routes Evaluate ----- #

@app.route('/admin/recommender_dashboard')
@admin_required
def recommender_dashboard():
    # Get last 7 days of data
    baselines = EvaluationBaseline.query.order_by(EvaluationBaseline.date.desc()).limit(7).all()
    
    # Prepare chart data
    dates = [b.date.strftime('%Y-%m-%d') for b in baselines][::-1]
    hybrid_ctr = [(b.hybrid_clicks / b.hybrid_impressions * 100) if b.hybrid_impressions > 0 else 0 for b in baselines][::-1]
    popular_ctr = [(b.popular_clicks / b.popular_impressions * 100) if b.popular_impressions > 0 else 0 for b in baselines][::-1]
    random_ctr = [(b.random_clicks / b.random_impressions * 100) if b.random_impressions > 0 else 0 for b in baselines][::-1]
    
    # Today's metrics
    today = datetime.utcnow().date()
    today_data = EvaluationBaseline.query.filter_by(date=today).first()
    
    return render_template('admin/recommender_dashboard.html',
                         dates=dates,
                         hybrid_ctr=hybrid_ctr,
                         popular_ctr=popular_ctr,
                         random_ctr=random_ctr,
                         today=today_data)

@app.route('/api/track_impression/<int:article_id>', methods=['POST'])
@login_required
def track_impression(article_id,strategy):
    try:
        data = request.get_json() or {}
        if not strategy:
            strategy = data.get('strategy', 'hybrid')
        
        track = RecommendationEvaluation(
            user_id=current_user.id,
            article_id=article_id,
            recommendation_strategy=strategy
        )
        db.session.add(track)
        db.session.commit()
        return jsonify({'status': 'success'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/track_click/<int:article_id>', methods=['POST'])
@login_required
def track_click(article_id):
    """Log when a user clicks a recommendation"""
    data = request.get_json()
    strategy = data.get('strategy', 'hybrid')
    
    # Update the most recent impression
    track = RecommendationEvaluation.query.filter_by(
        user_id=current_user.id,
        article_id=article_id,
        recommendation_strategy=strategy
    ).order_by(RecommendationEvaluation.shown_at.desc()).first()
    
    if track:
        track.clicked = True
        track.clicked_at = datetime.utcnow()
        db.session.commit()
    return jsonify({'status': 'success'})

@app.route('/api/track_save/<int:article_id>', methods=['POST'])
@login_required
def track_save(article_id):
    """Log when a user saves a recommended article"""
    data = request.get_json()
    strategy = data.get('strategy', 'hybrid')
    
    track = RecommendationEvaluation.query.filter_by(
        user_id=current_user.id,
        article_id=article_id,
        recommendation_strategy=strategy
    ).order_by(RecommendationEvaluation.shown_at.desc()).first()
    
    if track:
        track.saved = True
        db.session.commit()
    return jsonify({'status': 'success'})

# ---------------------------#




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
    """API endpoint to fetch articles for the homepage with new recommendation split."""
    articles = Article.query.order_by(Article.published_at.desc()).all()

    # Guest users see all news in general feed
    if not current_user.is_authenticated:
        return jsonify({'general': [article.to_dict() for article in articles]})

    total_count = len(articles)
    rec_count = max(1, int(total_count * 0.10))

    # 70% hybrid
    hybrid_count = int(rec_count * 0.70)
    recommender = HybridRecommender(db)
    hybrid_articles = recommender.get_recommendations(current_user.id, hybrid_count)

    # 15% popular
    popular_count = max(1, int(rec_count * 0.15))
    popular_articles = Article.query.order_by(Article.published_at.desc()).limit(popular_count).all()

    # 15% random
    random_count = rec_count - hybrid_count - popular_count
    random_articles = Article.query.order_by(db.func.random()).limit(random_count).all()

    # Combine and deduplicate recommendations
    rec_articles = list({a.id: a for a in (hybrid_articles + popular_articles + random_articles)}.values())

    # General feed = all articles except recommendations
    rec_ids = {a.id for a in rec_articles}
    general_articles = [a for a in articles if a.id not in rec_ids]

    # Track impressions for each strategy
    for a in hybrid_articles:
        db.session.add(RecommendationEvaluation(
            user_id=current_user.id, article_id=a.id, recommendation_strategy='hybrid'))
    for a in popular_articles:
        db.session.add(RecommendationEvaluation(
            user_id=current_user.id, article_id=a.id, recommendation_strategy='popular'))
    for a in random_articles:
        db.session.add(RecommendationEvaluation(
            user_id=current_user.id, article_id=a.id, recommendation_strategy='random'))
    db.session.commit()

    return jsonify({
        'recommendations': [a.to_dict() for a in rec_articles],
        'general': [a.to_dict() for a in general_articles]
    })


@app.route('/api/recommendations')
@login_required
def get_recommendations():
    """Modified to include strategy tracking"""
    # Determine strategy (simple A/B test)
    strategies = ['hybrid', 'popular', 'random']
    strategy = random.choices(strategies, weights=[70, 15, 15], k=1)[0]
    
    # Get recommendations based on strategy
    if strategy == 'hybrid':
        recommender = HybridRecommender(db)
        articles = recommender.get_recommendations(current_user.id)
    elif strategy == 'popular':
        articles = Article.query.order_by(Article.published_at.desc()).limit(10).all()
    else:  # random
        articles = Article.query.order_by(db.func.random()).limit(10).all()
    
    # Log impressions
    for article in articles:
        track_impression(article.id, strategy)
    
    return jsonify({
        'articles': [article.to_dict() for article in articles],
        'strategy': strategy
    }), 200  # Explicitly return 200 status

@app.route('/api/recommender_metrics')
@admin_required
def recommender_metrics():
    """API endpoint to fetch metrics for the dashboard"""
    # Get last 7 days of data
    baselines = EvaluationBaseline.query.order_by(EvaluationBaseline.date.desc()).limit(7).all()
    baselines = sorted(baselines, key=lambda x: x.date)  # Sort chronologically
    
    # Prepare trend data
    dates = [b.date.strftime('%Y-%m-%d') for b in baselines]
    
    hybrid_ctr = []
    popular_ctr = []
    random_ctr = []
    hybrid_save_rate = []
    popular_save_rate = []
    random_save_rate = []
    
    for b in baselines:
        # CTR calculations
        hybrid_ctr.append((b.hybrid_clicks / b.hybrid_impressions * 100) if b.hybrid_impressions > 0 else 0)
        popular_ctr.append((b.popular_clicks / b.popular_impressions * 100) if b.popular_impressions > 0 else 0)
        random_ctr.append((b.random_clicks / b.random_impressions * 100) if b.random_impressions > 0 else 0)
        
        # Save rate calculations
        hybrid_save_rate.append((b.hybrid_saves / b.hybrid_impressions * 100) if b.hybrid_impressions > 0 else 0)
        popular_save_rate.append((b.popular_saves / b.popular_impressions * 100) if b.popular_impressions > 0 else 0)
        random_save_rate.append((b.random_saves / b.random_impressions * 100) if b.random_impressions > 0 else 0)
    
    # Today's data (most recent)
    today = baselines[-1] if baselines else None
    
    return jsonify({
        'today': {
            'hybrid_impressions': today.hybrid_impressions if today else 0,
            'hybrid_clicks': today.hybrid_clicks if today else 0,
            'popular_impressions': today.popular_impressions if today else 0,
            'popular_clicks': today.popular_clicks if today else 0,
            'random_impressions': today.random_impressions if today else 0,
            'random_clicks': today.random_clicks if today else 0,
            'hybrid_saves': today.hybrid_saves if today else 0,
            'popular_saves': today.popular_saves if today else 0,
            'random_saves': today.random_saves if today else 0
        },
        'trend_dates': dates,
        'hybrid_ctr': hybrid_ctr,
        'popular_ctr': popular_ctr,
        'random_ctr': random_ctr,
        'hybrid_save_rate': hybrid_save_rate,
        'popular_save_rate': popular_save_rate,
        'random_save_rate': random_save_rate
    })
    
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

        scraper = MultiNewsScraper() 
        try:
            saved_count = scraper.scrape_and_save(category_url, max_articles=max_articles)
            flash(f'Successfully scraped and saved {saved_count} new articles from {category_url}.', 'success')
        except Exception as e:
            flash(f'Error during scraping: {e}', 'error')
            import traceback
            traceback.print_exc()
        return redirect(url_for('admin_articles'))
    return render_template('admin/scrape_news.html')

if __name__ == '__main__':
    # Initialize database first
    with app.app_context():
        db.create_all()
        initialize_database()
        
    
    # Register and start scheduler
    register_scheduler()
    
    try:
        app.run(debug=True)
    except (KeyboardInterrupt, SystemExit):
        # Proper shutdown
        scheduler.shutdown()
        raise