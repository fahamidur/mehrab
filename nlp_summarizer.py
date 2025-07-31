# nlp_summarizer.py
import spacy
from heapq import nlargest
from string import punctuation
from datetime import datetime

class ArticleSummarizer:
    def __init__(self):
        try:
            self.nlp = spacy.load('en_core_web_sm')
        except OSError:
            import subprocess
            subprocess.run(["python", "-m", "spacy", "download", "en_core_web_sm"])
            self.nlp = spacy.load('en_core_web_sm')

    def generate_summary(self, text, max_sentences=3):
        """Generate an extractive summary using spaCy"""
        if not text or len(text.split()) < 50:
            return None
            
        doc = self.nlp(text)
        word_frequencies = {}
        
        for word in doc:
            if word.text.lower() not in list(punctuation) and not word.is_stop:
                word_frequencies[word.text] = word_frequencies.get(word.text, 0) + 1
                
        max_frequency = max(word_frequencies.values()) if word_frequencies else 1
        for word in word_frequencies:
            word_frequencies[word] /= max_frequency
            
        sentence_scores = {}
        for sent in doc.sents:
            for word in sent:
                if word.text.lower() in word_frequencies:
                    sentence_scores[sent] = sentence_scores.get(sent, 0) + word_frequencies[word.text.lower()]
        
        summary_sentences = nlargest(max_sentences, sentence_scores, key=sentence_scores.get)
        return ' '.join([sent.text for sent in summary_sentences])

def summarize_new_articles(app, db, Article):
    """Summarize only newly scraped articles without summaries"""
    with app.app_context():
        summarizer = ArticleSummarizer()
        articles = Article.query.filter((Article.summary == "Loading Soon ...")).all()
        
        for article in articles:
            if article.content:
                article.summary = summarizer.generate_summary(article.content)
        
        db.session.commit()