from flask import Flask, request, render_template, jsonify
from flask_sqlalchemy import SQLAlchemy
import re
from datetime import datetime
import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import os

# App Configuration
app = Flask(__name__)#it is used to create an app in flask
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'phishingdb.sqlite3')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Database Model
class URLCheck(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=True)
    email = db.Column(db.String(120), nullable=True)
    result = db.Column(db.String(50), nullable=False)
    reasons = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Rule-Based URL Detection
def rule_based_check(url):
    suspicious_keywords = [
        'login', 'verify', 'update', 'banking', 'secure', 'account',
        'webscr', 'signin', 'wp-admin', 'payment', 'confirm', 'security',
        'ebayisapi', 'paypal'
    ]
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']
    reasons = []

    if re.match(r'^https?:\/\/\d+\.\d+\.\d+\.\d+', url):
        reasons.append("Uses IP address instead of domain")# ip address insted of domain name
    if '@' in url:
        reasons.append("Contains '@' symbol (used to redirect)")
    if '-' in url.split('//')[-1].split('/')[0]:
        reasons.append("Hyphen in domain name")
    domain_parts = url.split('//')[-1].split('/')[0].split('.')
    if len(domain_parts) > 3:
        reasons.append("Too many subdomains")
    for keyword in suspicious_keywords:
        if keyword in url.lower():
            reasons.append(f"Suspicious keyword: {keyword}")
    if re.search(r'(bit\.ly|tinyurl\.com|goo\.gl|t\.co|ow\.ly)', url):
        reasons.append("Uses URL shortener")
    for tld in suspicious_tlds:
        if url.endswith(tld):
            reasons.append(f"Suspicious TLD: {tld}")
    if len(re.findall(r'[!@#$%^&*(),]', url)) > 3:
        reasons.append("Too many special characters")

    return reasons

# Web Scraping
def scrape_webpage(url):# it use for fetch web page 
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        password_inputs = soup.find_all('input', {'type': 'password'})
        if forms and password_inputs:
            return ["Page contains form(s) with password field(s)"]
        else:
            return []
    except Exception as e:
        return [f"Scraping error: {str(e)}"]

# Selenium Redirect Check
def selenium_redirect_check(url):#it help to check and open url
    try:
        chrome_options = Options()
        chrome_options.add_argument('--headless')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        driver = webdriver.Chrome(options=chrome_options)

        driver.get(url)
        final_url = driver.current_url
        driver.quit()

        if final_url != url:
            return [f"Redirect detected to {final_url}"]
        else:
            return []
    except Exception as e:
        return [f"Selenium error: {str(e)}"]

# Save  in Database
def save_result_to_db(url, email, result, reasons):
    entry = URLCheck(
        url=url,
        email=email,
        result=result,
        reasons='; '.join(reasons)
    )
    db.session.add(entry)
    db.session.commit()

# Full URL Check 
def full_url_check(url):
    reasons = []
    reasons += rule_based_check(url)
    reasons += scrape_webpage(url)
    reasons += selenium_redirect_check(url)

    result = "Phishing" if reasons else "Legitimate"
    if not reasons:
        reasons = ["No suspicious activity detected"]
    return result, reasons

# Email Check 
def email_check(email):
    reasons = []
    email_pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    if not re.match(email_pattern, email):
        reasons.append("Invalid email format")
    if email.endswith(('.tk', '.ml', '.ga', '.cf', '.gq')):
        reasons.append("Suspicious free domain email")
    if email.count('@') != 1:
        reasons.append("Multiple '@' symbols in email")

    result = "Phishing" if reasons else "Legitimate"
    if not reasons:
        reasons = ["Email format looks fine"]
    return result, reasons

# Routes 
@app.route('/', methods=['GET', 'POST'])# get show the main page  and post accept the Url and the email
def index():
    result = ""
    reasons = []
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        email = request.form.get('email', '').strip()

        if url:
            result, reasons = full_url_check(url)# it call full URL  for checking
            save_result_to_db(url, None, result, reasons)
        elif email:
            result, reasons = email_check(email)
            save_result_to_db(None, email, result, reasons)
        else:
            result = "Error"
            reasons = ["Please enter a URL or Email."]
    return render_template('main.html', result=result, reasons=reasons)

#  History Route 
@app.route('/history')# it help to connect with the history page 
def history():
    all_entries = URLCheck.query.order_by(URLCheck.timestamp.desc()).all()
    return render_template('history.html', entries=all_entries)

# Run 
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, threaded=True)
