from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash


db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(10), default='user', nullable=False)
    saved_articles = db.relationship('SavedArticle', backref='user', lazy=True)
    email = db.Column(db.String(120), unique=True, nullable=False)

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