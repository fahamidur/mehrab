# models.py (updated)
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

# Just keep the db instance here since it's used by nlp_summarizer.py
db = SQLAlchemy()