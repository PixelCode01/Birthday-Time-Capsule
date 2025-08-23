from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, Response, session, send_file
from datetime import datetime, date, timedelta
import sqlite3
import hashlib
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import json
import random
import secrets
import logging
from logging.handlers import RotatingFileHandler
from functools import wraps
import io
import smtplib
from email.message import EmailMessage
import re
import zipfile
import csv

# QR code generation
import qrcode

# Security & forms
from flask_wtf import CSRFProtect
from flask_wtf.csrf import generate_csrf
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_compress import Compress
from werkzeug.middleware.proxy_fix import ProxyFix
from dotenv import load_dotenv

# Sanitization
import bleach
from apscheduler.schedulers.background import BackgroundScheduler

load_dotenv()

app = Flask(__name__)

# Core configuration (env-first with sensible defaults)
app.config.update(
    SECRET_KEY=os.getenv('SECRET_KEY') or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE=os.getenv('SESSION_COOKIE_SAMESITE', 'Lax'),
    SESSION_COOKIE_SECURE=os.getenv('SESSION_COOKIE_SECURE', 'false').lower() == 'true',
    PREFERRED_URL_SCHEME=os.getenv('PREFERRED_URL_SCHEME', 'http'),
)

# Respect proxy headers if behind a reverse proxy (e.g., fly.io, Render, nginx)
if os.getenv('TRUST_PROXY', 'false').lower() == 'true':
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

# Basic logging configuration (rotating file)
if not os.path.exists('logs'):
    try:
        os.makedirs('logs')
    except Exception:
        pass
log_handler = RotatingFileHandler(os.path.join('logs', 'app.log'), maxBytes=1_000_000, backupCount=3)
log_handler.setLevel(logging.INFO)
log_formatter = logging.Formatter('[%(asctime)s] %(levelname)s in %(module)s: %(message)s')
log_handler.setFormatter(log_formatter)
app.logger.addHandler(log_handler)
app.logger.setLevel(logging.INFO)

# CSRF protection
csrf = CSRFProtect(app)

# Make csrf_token available in templates
@app.context_processor
def inject_csrf():
    return dict(csrf_token=lambda: generate_csrf())

# Security headers via Talisman (relaxed CSP for current inline scripts/styles & CDNs)
csp = {
    'default-src': ["'self'"],
    'script-src': [
        "'self'",
        "'unsafe-inline'",
        'https://cdn.jsdelivr.net',
        'https://cdnjs.cloudflare.com'
    ],
    'style-src': [
        "'self'",
        "'unsafe-inline'",
        'https://cdn.jsdelivr.net',
        'https://fonts.googleapis.com',
        'https://cdnjs.cloudflare.com'
    ],
    'font-src': [
        "'self'",
        'https://fonts.gstatic.com',
        'https://cdnjs.cloudflare.com'
    ],
    'img-src': ["'self'", 'data:'],
    'media-src': ["'self'", 'data:'],
    'connect-src': ["'self'"],
}
Talisman(
    app,
    content_security_policy=csp,
    force_https=os.getenv('FORCE_HTTPS', 'false').lower() == 'true',
    frame_options='SAMEORIGIN',
    strict_transport_security=os.getenv('FORCE_HTTPS', 'false').lower() == 'true'
)

# Rate limiting (memory storage by default)
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=os.getenv('RATELIMIT_STORAGE_URI') or None
)
limiter.init_app(app)

# Compression for JSON/HTML responses
Compress(app)

DATABASE = os.getenv('DATABASE_URL', 'time_capsule.db')

def init_db():
    with sqlite3.connect(DATABASE) as conn:
        # Pragmas to improve reliability on SQLite
        try:
            conn.execute('PRAGMA journal_mode=WAL;')
            conn.execute('PRAGMA synchronous=NORMAL;')
        except Exception:
            pass
        conn.execute('''
            CREATE TABLE IF NOT EXISTS capsules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                birthdate TEXT NOT NULL,
                unlock_date TEXT NOT NULL,
                encrypted_data TEXT NOT NULL,
                theme TEXT DEFAULT 'default',
                privacy_level TEXT DEFAULT 'friends',
                owner_pin_hash TEXT,
                access_pin_hash TEXT,
                owner_email TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.execute('''
            CREATE TABLE IF NOT EXISTS contributions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                capsule_id INTEGER,
                contributor_name TEXT NOT NULL,
                message TEXT,
                ascii_art TEXT,
                image_data TEXT,
                contribution_type TEXT DEFAULT 'message',
                contributor_email TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (capsule_id) REFERENCES capsules (id)
            )
        ''')

        conn.execute('''
            CREATE TABLE IF NOT EXISTS invites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                capsule_id INTEGER,
                email TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                invited_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_attempt_at TIMESTAMP,
                reminder_sent_at TIMESTAMP,
                FOREIGN KEY (capsule_id) REFERENCES capsules (id)
            )
        ''')

        # Best-effort add missing columns for existing DBs
        try:
            conn.execute('ALTER TABLE capsules ADD COLUMN owner_pin_hash TEXT')
        except Exception:
            pass
        try:
            conn.execute('ALTER TABLE capsules ADD COLUMN access_pin_hash TEXT')
        except Exception:
            pass
        try:
            conn.execute('ALTER TABLE capsules ADD COLUMN owner_email TEXT')
        except Exception:
            pass
        try:
            conn.execute('ALTER TABLE contributions ADD COLUMN contributor_email TEXT')
        except Exception:
            pass
        # Add reminder_sent_at to invites if missing
        try:
            conn.execute('ALTER TABLE invites ADD COLUMN reminder_sent_at TIMESTAMP')
        except Exception:
            pass

        # New improvements: optional vanity slug and passphrase hint
        try:
            conn.execute('ALTER TABLE capsules ADD COLUMN slug TEXT')
        except Exception:
            pass
        try:
            conn.execute('ALTER TABLE capsules ADD COLUMN passphrase_hint TEXT')
        except Exception:
            pass
        # Owner email verification + magic link support
        try:
            conn.execute('ALTER TABLE capsules ADD COLUMN owner_email_verified INTEGER DEFAULT 0')
        except Exception:
            pass
        try:
            conn.execute('ALTER TABLE capsules ADD COLUMN owner_verify_token TEXT')
        except Exception:
            pass
        try:
            conn.execute('ALTER TABLE capsules ADD COLUMN owner_magic_token TEXT')
        except Exception:
            pass
        try:
            conn.execute('ALTER TABLE capsules ADD COLUMN owner_magic_expires TEXT')
        except Exception:
            pass
        # Invite RSVP tracking
        try:
            conn.execute('ALTER TABLE invites ADD COLUMN token TEXT')
        except Exception:
            pass
        try:
            conn.execute('ALTER TABLE invites ADD COLUMN rsvp_at TIMESTAMP')
        except Exception:
            pass
        try:
            conn.execute('ALTER TABLE invites ADD COLUMN contributed_at TIMESTAMP')
        except Exception:
            pass

email_regex = re.compile(r"^(?=.{3,254}$)[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

def is_valid_email(addr: str) -> bool:
    if not addr or len(addr) > 254:
        return False
    if not email_regex.match(addr):
        return False
    # disallow consecutive dots in local or domain parts
    local, _, domain = addr.partition('@')
    if '..' in local or '..' in domain:
        return False
    return True

def hash_pin(pin: str) -> str:
    return hashlib.sha256(pin.encode('utf-8')).hexdigest()


slug_clean_re = re.compile(r'[^a-z0-9-]')

def slugify(name: str) -> str:
    base = (name or '').strip().lower()
    base = base.replace(' ', '-')
    base = slug_clean_re.sub('', base)
    base = re.sub(r'-{2,}', '-', base).strip('-')
    if not base:
        base = 'capsule'
    return base[:40]

def ensure_unique_slug(conn: sqlite3.Connection, desired: str) -> str:
    """Ensure slug is unique; append short suffix if needed."""
    slug = desired
    cur = conn.cursor()
    i = 0
    while True:
        cur.execute('SELECT 1 FROM capsules WHERE lower(slug) = lower(?) LIMIT 1', (slug,))
        if not cur.fetchone():
            return slug
        i += 1
        slug = f"{desired}-{i}"

def get_time_until_unlock(unlock_date_str):
    unlock_date = datetime.strptime(unlock_date_str, '%Y-%m-%d').date()
    today = date.today()
    if today >= unlock_date:
        return None
    
    delta = unlock_date - today
    years = delta.days // 365
    months = (delta.days % 365) // 30
    days = delta.days % 30
    
    if years > 0:
        return f"{years} year{'s' if years != 1 else ''}, {months} month{'s' if months != 1 else ''}"
    elif months > 0:
        return f"{months} month{'s' if months != 1 else ''}, {days} day{'s' if days != 1 else ''}"
    else:
        return f"{delta.days} day{'s' if delta.days != 1 else ''}"

def generate_birthday_extras():
    horoscopes = [
        "This year brings new adventures and wonderful surprises. Your creativity will shine bright!",
        "Amazing opportunities await you this year. Trust your instincts and embrace change!",
        "Your kindness will come back to you tenfold this year. Spread joy wherever you go!",
        "This birthday marks the beginning of your most exciting chapter yet!",
        "The stars align perfectly for you this year. Dream big and make it happen!"
    ]
    
    playlist_songs = [
        ["Happy Birthday", "Celebration", "Good as Hell", "Dancing Queen", "Uptown Funk"],
        ["Birthday", "Party Rock Anthem", "Can't Stop the Feeling", "Shake It Off", "September"],
        ["Celebrate", "I Gotta Feeling", "Happy", "Best Day of My Life", "Counting Stars"],
        ["Good Time", "Firework", "Roar", "Stronger", "What Makes You Beautiful"]
    ]
    
    return {
        'horoscope': random.choice(horoscopes),
        'lucky_number': random.randint(1, 99),
        'playlist': random.choice(playlist_songs)
    }

def generate_key(birthdate, passphrase):
    password = f"{birthdate}{passphrase}".encode()
    salt = b'birthday_capsule_salt'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

def encrypt_data(data, key):
    f = Fernet(key)
    return f.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data, key):
    f = Fernet(key)
    return f.decrypt(encrypted_data.encode()).decode()


def days_until(date_str: str) -> int:
    try:
        target = datetime.strptime(date_str, '%Y-%m-%d').date()
        return (target - date.today()).days
    except Exception:
        return 99999


def send_unlock_reminders(now=None, stages=(7, 3, 1, 0)) -> int:
    """Send reminder emails to pending invites whose capsule unlock is near.
    Returns number of reminder emails attempted.
    """
    count = 0
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute('SELECT id, name, unlock_date FROM capsules')
        capsules = cur.fetchall()
        for cap in capsules:
            cid, cname, unlock_date = cap
            days = days_until(unlock_date)
            if days not in stages:
                continue
            # fetch pending invites
            cur.execute('''
                SELECT id, email, status, last_attempt_at FROM invites
                WHERE capsule_id = ? AND status = 'pending'
            ''', (cid,))
            invites = cur.fetchall()
            for inv in invites:
                inv_id, email_addr, status, last_attempt_at = inv
                # avoid multiple sends the same day
                should_send = True
                if last_attempt_at:
                    try:
                        last = datetime.fromisoformat(str(last_attempt_at))
                        if (datetime.utcnow() - last).total_seconds() < 20 * 60 * 60:
                            should_send = False
                    except Exception:
                        pass
                if not should_send:
                    continue
                if days == 0:
                    subject = f"Today: {cname}'s Time Capsule unlocks!"
                else:
                    subject = f"Reminder: {cname}'s Time Capsule unlocks in {days} day{'s' if days != 1 else ''}"
                contribute_url = url_for('contribute', capsule_id=cid, _external=True)
                details_url = url_for('capsule_details', capsule_id=cid, _external=True)
                body = (
                    ("It's unlock day! Celebrate and unlock the capsule.\n\n" if days == 0 else "You're invited to contribute before it unlocks!\n\n")
                    + f"Contribute: {contribute_url}\n"
                    + f"Capsule details: {details_url}\n"
                    + f"Unlock date: {unlock_date}\n\n"
                    + ("Unlock page requires the owner's passphrase.\n" if days == 0 else "If you've already contributed, thank you!\n")
                )
                sent = send_email(email_addr, subject, body)
                cur.execute('UPDATE invites SET last_attempt_at = CURRENT_TIMESTAMP WHERE id = ?', (inv_id,))
                count += 1 if sent else 0
        conn.commit()
    app.logger.info('Reminder job attempted sends: %s', count)
    return count


scheduler: BackgroundScheduler | None = None

def start_scheduler():
    global scheduler
    if scheduler is not None and scheduler.running:
        return
    try:
        scheduler = BackgroundScheduler(daemon=True)
        # Run every 12 hours to be safe on simple hosts
        scheduler.add_job(send_unlock_reminders, 'interval', hours=12, id='unlock_reminders', max_instances=1, coalesce=True)
        scheduler.start()
        app.logger.info('APScheduler started with unlock reminder job.')
    except Exception as e:
        app.logger.warning('Failed to start scheduler: %s', e)

# Simple health endpoint for uptime checks
@app.route('/health')
def health():
    resp = jsonify(status='ok')
    resp.headers['Cache-Control'] = 'no-store'
    return resp, 200

# Robots and sitemap for better SEO and crawler behavior
@app.route('/robots.txt')
def robots_txt():
    lines = [
        f"Sitemap: {url_for('sitemap', _external=True)}",
        "User-agent: *",
        "Disallow: /capsule/*/owner",
        "Disallow: /capsule/*/owner_login",
    ]
    return Response('\n'.join(lines), mimetype='text/plain')

@app.route('/sitemap.xml')
def sitemap():
    base = request.url_root.rstrip('/')
    static_urls = [
        url_for('index', _external=True),
        url_for('find_capsule', _external=True),
        url_for('create_capsule', _external=True),
    ]
    # Add capsule detail pages (top 50 most recent)
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute('SELECT id FROM capsules ORDER BY created_at DESC LIMIT 50')
        ids = [row[0] for row in cur.fetchall()]
    urls = static_urls + [url_for('capsule_details', capsule_id=i, _external=True) for i in ids]
    xml = [
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
        "<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">",
    ]
    for u in urls:
        xml.append("  <url>")
        xml.append(f"    <loc>{u}</loc>")
        xml.append("  </url>")
    xml.append("</urlset>")
    return Response('\n'.join(xml), mimetype='application/xml')

@app.route('/')
def index():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM capsules')
        total_capsules = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM contributions')
        total_contributions = cursor.fetchone()[0]
    
    return render_template('index.html', 
                         total_capsules=total_capsules,
                         total_contributions=total_contributions)

@app.route('/api/capsule_stats/<int:capsule_id>')
def capsule_stats(capsule_id):
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT unlock_date FROM capsules WHERE id = ?', (capsule_id,))
        capsule = cursor.fetchone()
        
        if not capsule:
            return jsonify({'error': 'Capsule not found'}), 404
        
        time_remaining = get_time_until_unlock(capsule[0])
        
        cursor.execute('SELECT COUNT(*) FROM contributions WHERE capsule_id = ?', (capsule_id,))
        contribution_count = cursor.fetchone()[0]
    
    return jsonify({
        'time_remaining': time_remaining,
        'contribution_count': contribution_count,
        'is_unlocked': time_remaining is None
    })

@app.route('/create_capsule', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def create_capsule():
    if request.method == 'POST':
        name = request.form['name']
        birthdate = request.form['birthdate']
        unlock_date = request.form['unlock_date']
        passphrase = request.form['passphrase']
        future_letter = request.form['future_letter']
        theme = request.form.get('theme', 'default')
        privacy_level = request.form.get('privacy_level', 'friends')
        owner_pin = request.form.get('owner_pin', '').strip()
        access_pin = request.form.get('access_pin', '').strip()
        owner_email = request.form.get('owner_email', '').strip()
        passphrase_hint = request.form.get('passphrase_hint', '').strip() or None
        desired_slug = request.form.get('slug', '').strip().lower()

        # Validate unlock date
        unlock_dt = datetime.strptime(unlock_date, '%Y-%m-%d').date()
        if unlock_dt <= date.today():
            flash('Unlock date must be in the future!', 'error')
            return render_template('create_capsule.html')

        key = generate_key(birthdate, passphrase)

        # Sanitize user-provided letter, preserving simple formatting
        future_letter_sanitized = bleach.clean(
            future_letter.replace('\n', '<br>'),
            tags=['br', 'b', 'strong', 'i', 'em', 'u', 'a'],
            attributes={'a': ['href', 'title', 'rel', 'target']},
            strip=True,
        )
        # Ensure links open safely by default
        future_letter_sanitized = future_letter_sanitized.replace('<a ', "<a rel=\"noopener noreferrer\" target=\"_blank\" ")

        capsule_data = {
            'future_letter': future_letter_sanitized,
            'theme': theme,
            'privacy_level': privacy_level,
            'contributions': []
        }

        encrypted_data = encrypt_data(json.dumps(capsule_data), key)

        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            # Prepare slug
            if desired_slug:
                # normalize
                desired_slug = slugify(desired_slug)
            else:
                desired_slug = slugify(name)
            slug = ensure_unique_slug(conn, desired_slug)
            # Owner verification token if email is provided
            verify_token = None
            if owner_email and is_valid_email(owner_email):
                verify_token = secrets.token_urlsafe(20)
            cursor.execute('''
                INSERT INTO capsules (name, birthdate, unlock_date, encrypted_data, theme, privacy_level, owner_pin_hash, access_pin_hash, owner_email, slug, passphrase_hint, owner_email_verified, owner_verify_token)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                name, birthdate, unlock_date, encrypted_data, theme, privacy_level,
                hash_pin(owner_pin) if owner_pin else None,
                hash_pin(access_pin) if access_pin else None,
                owner_email if owner_email and is_valid_email(owner_email) else None,
                slug,
                passphrase_hint,
                0,
                verify_token
            ))
            capsule_id = cursor.lastrowid

        # Best-effort owner verification email
        try:
            if verify_token:
                verify_url = url_for('verify_owner', capsule_id=capsule_id, token=verify_token, _external=True)
                send_email(owner_email, f"Verify your email for {name}'s Time Capsule", f"Please verify your email: {verify_url}")
        except Exception as e:
            app.logger.info('Owner verification email skipped: %s', e)

        flash(f'Time capsule created successfully! Share ID: {capsule_id}', 'success')
        return redirect(url_for('capsule_details', capsule_id=capsule_id))

    return render_template('create_capsule.html')

@app.route('/capsule/<int:capsule_id>')
def capsule_details(capsule_id):
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM capsules WHERE id = ?', (capsule_id,))
        capsule = cursor.fetchone()
        
        if not capsule:
            flash('Capsule not found!', 'error')
            return redirect(url_for('index'))
        
        cursor.execute('SELECT * FROM contributions WHERE capsule_id = ? ORDER BY created_at DESC', (capsule_id,))
        contributions = cursor.fetchall()
    
    unlock_date = datetime.strptime(capsule[3], '%Y-%m-%d').date()
    is_unlocked = date.today() >= unlock_date
    time_remaining = get_time_until_unlock(capsule[3])
    owner_authed = session.get(f'owner_auth_{capsule_id}', False)
    
    return render_template('capsule_details.html', 
                         capsule=capsule, 
                         contributions=contributions,
                         is_unlocked=is_unlocked,
                         unlock_date=unlock_date,
                         time_remaining=time_remaining,
                         owner_authed=owner_authed)


# Vanity slug routes
@app.route('/c/<slug>')
def capsule_details_slug(slug):
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute('SELECT id FROM capsules WHERE lower(slug) = lower(?)', (slug,))
        row = cur.fetchone()
    if not row:
        flash('Capsule not found.', 'error')
        return redirect(url_for('index'))
    return redirect(url_for('capsule_details', capsule_id=row[0]))

@app.route('/c/<slug>/contribute', methods=['GET', 'POST'])
def contribute_slug(slug):
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute('SELECT id FROM capsules WHERE lower(slug) = lower(?)', (slug,))
        row = cur.fetchone()
    if not row:
        flash('Capsule not found.', 'error')
        return redirect(url_for('index'))
    return contribute(row[0])

@app.route('/c/<slug>/unlock', methods=['GET', 'POST'])
def unlock_slug(slug):
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute('SELECT id FROM capsules WHERE lower(slug) = lower(?)', (slug,))
        row = cur.fetchone()
    if not row:
        flash('Capsule not found.', 'error')
        return redirect(url_for('index'))
    return unlock_capsule(row[0])

@app.route('/c/<slug>/qr')
def capsule_qr_slug(slug):
    # Generate a QR for the contribute URL using slug
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute('SELECT id FROM capsules WHERE lower(slug) = lower(?)', (slug,))
        row = cur.fetchone()
    if not row:
        return jsonify({'error': 'Capsule not found'}), 404
    url = url_for('contribute_slug', slug=slug, _external=True)
    img = qrcode.make(url)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return send_file(buf, mimetype='image/png', download_name=f'capsule_{row[0]}_{slug}_qr.png')

@app.route('/contribute/<int:capsule_id>', methods=['GET', 'POST'])
@limiter.limit("10 per hour")
def contribute(capsule_id):
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM capsules WHERE id = ?', (capsule_id,))
        capsule = cursor.fetchone()
        
        if not capsule:
            flash('Capsule not found!', 'error')
            return redirect(url_for('index'))
        
        unlock_date = datetime.strptime(capsule[3], '%Y-%m-%d').date()
        if date.today() >= unlock_date:
            flash('This capsule has already been unlocked!', 'warning')
            return redirect(url_for('capsule_details', capsule_id=capsule_id))

        # Enforce private access PIN when required
        privacy_level = capsule[6]
        access_pin_hash = capsule[8] if len(capsule) > 8 else None
        if privacy_level == 'private' or access_pin_hash:
            if not session.get(f'capsule_access_{capsule_id}'):
                return redirect(url_for('access_capsule', capsule_id=capsule_id))
    
    if request.method == 'POST':
        contributor_name = request.form['contributor_name']
        message = request.form.get('message', '')
        ascii_art = request.form.get('ascii_art', '')
        contribution_type = request.form.get('contribution_type', 'message')
        contributor_email = request.form.get('contributor_email', '').strip()
        
        if not any([message, ascii_art, 'image' in request.files]):
            flash('Please add at least one type of contribution!', 'warning')
            return render_template('contribute.html', capsule=capsule)
        
        image_data = ''
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename:
                # Basic size check
                if file.content_length and file.content_length > 5 * 1024 * 1024:
                    flash('Image file too large! Please use files smaller than 5MB.', 'error')
                    return render_template('contribute.html', capsule=capsule)
                # Basic MIME/type check; Werkzeug may not always populate mimetype from content
                allowed_mimes = {'image/png', 'image/jpeg', 'image/gif', 'image/webp'}
                if not (file.mimetype and (file.mimetype in allowed_mimes or file.mimetype.startswith('image/'))):
                    flash('Unsupported image type. Please upload PNG, JPEG, GIF, or WEBP.', 'error')
                    return render_template('contribute.html', capsule=capsule)
                image_data = base64.b64encode(file.read()).decode()
        
        # Sanitize message, allow basic formatting and links; preserve line breaks
        message_sanitized = ''
        if message:
            message_sanitized = bleach.clean(
                message.replace('\n', '<br>'),
                tags=['br', 'b', 'strong', 'i', 'em', 'u', 'a'],
                attributes={'a': ['href', 'title', 'rel', 'target']},
                strip=True,
            )
            message_sanitized = message_sanitized.replace('<a ', "<a rel=\"noopener noreferrer\" target=\"_blank\" ")

        # Strip any HTML from ASCII art entirely (render as text)
        ascii_art_sanitized = ''
        if ascii_art:
            ascii_art_sanitized = bleach.clean(ascii_art, tags=[], strip=True)

        with sqlite3.connect(DATABASE) as conn:
            conn.execute('''
                INSERT INTO contributions (capsule_id, contributor_name, message, ascii_art, image_data, contribution_type, contributor_email)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (capsule_id, contributor_name, message_sanitized, ascii_art_sanitized, image_data, contribution_type, contributor_email if contributor_email and is_valid_email(contributor_email) else None))
            # Mark matching invite as contributed
            if contributor_email and is_valid_email(contributor_email):
                try:
                    conn.execute("""
                        UPDATE invites SET status = 'contributed', contributed_at = CURRENT_TIMESTAMP
                        WHERE capsule_id = ? AND lower(email) = lower(?) AND status != 'revoked'
                    """, (capsule_id, contributor_email))
                except Exception:
                    pass

        # Notify contributor (thank you) and owner (new contribution)
        try:
            with sqlite3.connect(DATABASE) as conn:
                cur = conn.cursor()
                cur.execute('SELECT name, unlock_date, owner_email FROM capsules WHERE id = ?', (capsule_id,))
                row = cur.fetchone()
            if row:
                owner_email_addr = row[2]
                details_url = url_for('capsule_details', capsule_id=capsule_id, _external=True)
                if contributor_email and is_valid_email(contributor_email):
                    send_email(
                        contributor_email,
                        f"Thanks for contributing to {row[0]}'s Time Capsule",
                        f"Your message has been saved and will be revealed on {row[1]}. You can revisit the capsule here: {details_url}"
                    )
                if owner_email_addr and is_valid_email(owner_email_addr):
                    send_email(
                        owner_email_addr,
                        f"New contribution to {row[0]}'s Time Capsule",
                        f"{contributor_name} just added a contribution. Contents stay locked until {row[1]}. View capsule: {details_url}"
                    )
        except Exception as e:
            app.logger.info('Notification emails skipped: %s', e)
        
    flash('Your contribution has been added to the time capsule.', 'success')
    return redirect(url_for('capsule_details', capsule_id=capsule_id))
    
    return render_template('contribute.html', capsule=capsule)


@app.route('/capsule/<int:capsule_id>/kiosk', methods=['GET', 'POST'])
@limiter.limit("30 per hour")
def kiosk_mode(capsule_id):
    """Party/Kiosk mode for rapid-fire contributions during an event."""
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute('SELECT * FROM capsules WHERE id = ?', (capsule_id,))
        capsule = cur.fetchone()
        if not capsule:
            flash('Capsule not found!', 'error')
            return redirect(url_for('index'))
        unlock_date = datetime.strptime(capsule[3], '%Y-%m-%d').date()
        if date.today() >= unlock_date:
            flash('This capsule has already been unlocked!', 'warning')
            return redirect(url_for('capsule_details', capsule_id=capsule_id))
        # Respect access pin if set
        privacy_level = capsule[6]
        access_pin_hash = capsule[8] if len(capsule) > 8 else None
        if privacy_level == 'private' or access_pin_hash:
            if not session.get(f'capsule_access_{capsule_id}'):
                return redirect(url_for('access_capsule', capsule_id=capsule_id))

    if request.method == 'POST':
        name = request.form.get('contributor_name', '').strip()
        message = request.form.get('message', '').strip()
        ascii_art = request.form.get('ascii_art', '').strip()
        image_data = ''
        if 'image' in request.files:
            f = request.files['image']
            if f and f.filename:
                allowed_mimes = {'image/png', 'image/jpeg', 'image/gif', 'image/webp'}
                if f.mimetype and (f.mimetype in allowed_mimes or f.mimetype.startswith('image/')):
                    image_data = base64.b64encode(f.read()).decode()
        if not any([message, ascii_art, image_data]):
            flash('Please add a message, ASCII art, or image.', 'warning')
            return render_template('kiosk.html', capsule=capsule)
        # sanitize
        message_sanitized = bleach.clean(message.replace('\n', '<br>'), tags=['br','b','strong','i','em','u','a'], attributes={'a':['href','title','rel','target']}, strip=True) if message else ''
        if message_sanitized:
            message_sanitized = message_sanitized.replace('<a ', "<a rel=\"noopener noreferrer\" target=\"_blank\" ")
        ascii_sanitized = bleach.clean(ascii_art, tags=[], strip=True) if ascii_art else ''
        with sqlite3.connect(DATABASE) as conn:
            conn.execute('''
                INSERT INTO contributions (capsule_id, contributor_name, message, ascii_art, image_data, contribution_type)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (capsule_id, name or 'Guest', message_sanitized, ascii_sanitized, image_data, 'message' if message_sanitized else 'creative'))
        # Render thank-you and reset form
        return render_template('kiosk.html', capsule=capsule, just_submitted=True)

    return render_template('kiosk.html', capsule=capsule)

@app.route('/unlock/<int:capsule_id>', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def unlock_capsule(capsule_id):
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM capsules WHERE id = ?', (capsule_id,))
        capsule = cursor.fetchone()
        
        if not capsule:
            flash('Capsule not found!', 'error')
            return redirect(url_for('index'))
        
        unlock_date = datetime.strptime(capsule[3], '%Y-%m-%d').date()
        if date.today() < unlock_date:
            flash(f'This capsule can only be opened on {unlock_date.strftime("%B %d, %Y")}!', 'warning')
            return redirect(url_for('capsule_details', capsule_id=capsule_id))
    
    # Fetch hint (optional)
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute('SELECT passphrase_hint FROM capsules WHERE id = ?', (capsule_id,))
        r = cur.fetchone()
        passphrase_hint = r[0] if r else None

    if request.method == 'POST':
        passphrase = request.form['passphrase']
        
        try:
            key = generate_key(capsule[2], passphrase)
            decrypted_data = decrypt_data(capsule[4], key)
            capsule_data = json.loads(decrypted_data)
            
            # Fetch contributions in a fresh DB context
            with sqlite3.connect(DATABASE) as conn:
                cur2 = conn.cursor()
                cur2.execute('SELECT * FROM contributions WHERE capsule_id = ? ORDER BY created_at ASC', (capsule_id,))
                contributions = cur2.fetchall()
            
            birthday_extras = generate_birthday_extras()
            
            return render_template('reveal.html', 
                                 capsule=capsule,
                                 capsule_data=capsule_data,
                                 contributions=contributions,
                                 birthday_extras=birthday_extras)
        
        except Exception as e:
            app.logger.warning('Failed to unlock capsule %s: %s', capsule_id, e)
            flash('Invalid passphrase! Please try again.', 'error')
        return render_template('unlock.html', capsule=capsule, passphrase_hint=passphrase_hint)
    
    return render_template('unlock.html', capsule=capsule, passphrase_hint=passphrase_hint)

@app.route('/find_capsule', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def find_capsule():
    if request.method == 'POST':
        query = (request.form.get('query') or '').strip()
        # Accept numeric ID, slug, or full URL containing /c/<slug>
        if not query:
            return redirect(url_for('find_capsule'))
        # If it's a URL, try to extract slug after /c/
        m = re.search(r"/c/([a-z0-9-]{1,60})", query, re.IGNORECASE)
        if m:
            slug = m.group(1)
            return redirect(url_for('capsule_details_slug', slug=slug))
        # Pure numeric => treat as ID
        if query.isdigit():
            return redirect(url_for('capsule_details', capsule_id=int(query)))
        # Otherwise, treat as slug; validate-ish
        candidate = slugify(query)
        if candidate:
            return redirect(url_for('capsule_details_slug', slug=candidate))
        return redirect(url_for('find_capsule'))
    
    return render_template('find_capsule.html')


@app.route('/capsule/<int:capsule_id>/qr')
def capsule_qr(capsule_id):
    # Generate a QR for the contribute URL
    url = url_for('contribute', capsule_id=capsule_id, _external=True)
    img = qrcode.make(url)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return send_file(buf, mimetype='image/png', download_name=f'capsule_{capsule_id}_qr.png')


@app.route('/capsule/<int:capsule_id>/ics')
def capsule_ics(capsule_id):
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT name, unlock_date FROM capsules WHERE id = ?', (capsule_id,))
        row = cursor.fetchone()
        if not row:
            return jsonify({'error': 'Capsule not found'}), 404
        name, unlock_date_str = row

    # Build ICS content (all-day event on unlock date)
    try:
        unlock_date = datetime.strptime(unlock_date_str, '%Y-%m-%d').date()
    except Exception:
        unlock_date = date.today()
    dtstamp = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    dtstart = unlock_date.strftime('%Y%m%d')
    details_url = url_for('capsule_details', capsule_id=capsule_id, _external=True)
    summary = f"Unlock {name}'s Birthday Time Capsule"

    ics = (
        "BEGIN:VCALENDAR\r\n" 
        "VERSION:2.0\r\n"
        "PRODID:-//Birthday Time Capsule//EN\r\n"
        "CALSCALE:GREGORIAN\r\n"
        "METHOD:PUBLISH\r\n"
        "BEGIN:VEVENT\r\n"
        f"UID:{capsule_id}@birthday-time-capsule\r\n"
        f"DTSTAMP:{dtstamp}\r\n"
        f"DTSTART;VALUE=DATE:{dtstart}\r\n"
        f"SUMMARY:{summary}\r\n"
        f"DESCRIPTION:Open the capsule at {details_url}\r\n"
        f"URL:{details_url}\r\n"
        "BEGIN:VALARM\r\n"
        "ACTION:DISPLAY\r\n"
        "DESCRIPTION:Capsule unlocks in 7 days\r\n"
        "TRIGGER:-P7D\r\n"
        "END:VALARM\r\n"
        "BEGIN:VALARM\r\n"
        "ACTION:DISPLAY\r\n"
        "DESCRIPTION:Capsule unlocks tomorrow\r\n"
        "TRIGGER:-P1D\r\n"
        "END:VALARM\r\n"
        "END:VEVENT\r\n"
        "END:VCALENDAR\r\n"
    )

    resp = Response(ics, mimetype='text/calendar; charset=utf-8')
    resp.headers['Content-Disposition'] = f'attachment; filename=capsule_{capsule_id}_unlock.ics'
    resp.headers['Cache-Control'] = 'no-store'
    return resp


@app.route('/capsule/<int:capsule_id>/export.json')
def export_capsule(capsule_id):
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, name, birthdate, unlock_date, created_at FROM capsules WHERE id = ?', (capsule_id,))
        capsule = cursor.fetchone()
        if not capsule:
            return jsonify({'error': 'Capsule not found'}), 404
        # Count contributions and optionally include content based on unlock
        cursor.execute('SELECT * FROM contributions WHERE capsule_id = ? ORDER BY created_at ASC', (capsule_id,))
        contrib_rows = cursor.fetchall()

    unlock_date = datetime.strptime(capsule[3], '%Y-%m-%d').date()
    is_unlocked = date.today() >= unlock_date

    contributions = []
    for c in contrib_rows:
        item = {
            'id': c[0],
            'contributor_name': c[2],
            'created_at': c[7],
            'contribution_type': c[8]
        }
        if is_unlocked:
            item['message'] = c[3]
            item['ascii_art'] = c[4]
            item['image_data'] = c[5]
        else:
            item['has_message'] = bool(c[3])
            item['has_ascii_art'] = bool(c[4])
            item['has_image'] = bool(c[5])
        contributions.append(item)

    payload = {
        'capsule': {
            'id': capsule[0],
            'name': capsule[1],
            'birthdate': capsule[2],
            'unlock_date': capsule[3],
            'created_at': capsule[4],
            'is_unlocked': is_unlocked,
        },
        'contributions': contributions
    }

    resp = jsonify(payload)
    resp.headers['Cache-Control'] = 'no-store'
    resp.headers['Content-Disposition'] = f'attachment; filename=capsule_{capsule_id}.json'
    return resp


@app.route('/capsule/<int:capsule_id>/export.zip')
def export_zip(capsule_id):
    """Export a ZIP with JSON metadata and images."""
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute('SELECT id, name, birthdate, unlock_date, created_at FROM capsules WHERE id = ?', (capsule_id,))
        cap = cur.fetchone()
        if not cap:
            return jsonify({'error': 'Capsule not found'}), 404
        cur.execute('SELECT * FROM contributions WHERE capsule_id = ? ORDER BY created_at ASC', (capsule_id,))
        contribs = cur.fetchall()
    # Build JSON similar to export.json (always include content in ZIP; it's a personal export)
    items = []
    for c in contribs:
        items.append({
            'id': c[0],
            'contributor_name': c[2],
            'created_at': c[7],
            'contribution_type': c[8],
            'message': c[3],
            'ascii_art': c[4],
            'has_image': bool(c[5])
        })
    meta = {
        'capsule': {
            'id': cap[0], 'name': cap[1], 'birthdate': cap[2], 'unlock_date': cap[3], 'created_at': cap[4]
        },
        'contributions': items
    }
    mem = io.BytesIO()
    with zipfile.ZipFile(mem, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f'capsule_{capsule_id}.json', json.dumps(meta, indent=2))
        # write images
        img_idx = 1
        for c in contribs:
            img_b64 = c[5]
            if img_b64:
                try:
                    data = base64.b64decode(img_b64)
                    zf.writestr(f'images/contribution_{c[0]}_{img_idx}.jpg', data)
                    img_idx += 1
                except Exception:
                    pass
    mem.seek(0)
    resp = send_file(mem, mimetype='application/zip', download_name=f'capsule_{capsule_id}.zip', as_attachment=True)
    resp.headers['Cache-Control'] = 'no-store'
    return resp


 


@app.route('/api/capsule/<int:capsule_id>/share_links')
def api_share_links(capsule_id):
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute('SELECT slug FROM capsules WHERE id = ?', (capsule_id,))
        row = cur.fetchone()
        if not row:
            return jsonify({'error': 'Capsule not found'}), 404
        slug = row[0]
    links = {
        'details': url_for('capsule_details', capsule_id=capsule_id, _external=True),
        'contribute': url_for('contribute', capsule_id=capsule_id, _external=True),
        'unlock': url_for('unlock_capsule', capsule_id=capsule_id, _external=True),
    }
    if slug:
        links.update({
            'details_slug': url_for('capsule_details_slug', slug=slug, _external=True),
            'contribute_slug': url_for('contribute_slug', slug=slug, _external=True),
            'unlock_slug': url_for('unlock_slug', slug=slug, _external=True),
            'qr_slug_png': url_for('capsule_qr_slug', slug=slug, _external=True)
        })
    return jsonify({'capsule_id': capsule_id, 'slug': slug, 'links': links})


@app.route('/capsule/<int:capsule_id>/access', methods=['GET', 'POST'])
def access_capsule(capsule_id):
    # Access PIN for private contributions
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute('SELECT id, name, privacy_level, access_pin_hash FROM capsules WHERE id = ?', (capsule_id,))
        row = cur.fetchone()
        if not row:
            flash('Capsule not found!', 'error')
            return redirect(url_for('index'))
    if request.method == 'POST':
        pin = request.form.get('access_pin', '').strip()
        if row[3] and hash_pin(pin) == row[3]:
            session[f'capsule_access_{capsule_id}'] = True
            flash('Access granted.', 'success')
            return redirect(url_for('contribute', capsule_id=capsule_id))
        else:
            flash('Invalid PIN.', 'error')
    return render_template('access.html', capsule=(row[0], row[1], None, None, None, None))


@app.route('/capsule/<int:capsule_id>/owner_login', methods=['GET', 'POST'])
def owner_login(capsule_id):
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute('SELECT id, owner_pin_hash, name FROM capsules WHERE id = ?', (capsule_id,))
        row = cur.fetchone()
        if not row:
            flash('Capsule not found!', 'error')
            return redirect(url_for('index'))
    if request.method == 'POST':
        pin = request.form.get('owner_pin', '').strip()
        if row[1] and hash_pin(pin) == row[1]:
            session[f'owner_auth_{capsule_id}'] = True
            flash('Owner signed in.', 'success')
            return redirect(url_for('capsule_details', capsule_id=capsule_id))
        else:
            flash('Invalid owner PIN.', 'error')
    return render_template('owner_login.html', capsule_id=capsule_id)


def owner_required(fn):
    @wraps(fn)
    def wrapper(capsule_id, *args, **kwargs):
        if not session.get(f'owner_auth_{capsule_id}'):
            flash('Owner login required.', 'error')
            return redirect(url_for('owner_login', capsule_id=capsule_id))
        return fn(capsule_id, *args, **kwargs)
    return wrapper


@app.route('/capsule/<int:capsule_id>/export.csv')
@owner_required
def export_capsule_csv(capsule_id):
    # CSV export of contributions; hides content before unlock
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute('SELECT id, name, birthdate, unlock_date, created_at FROM capsules WHERE id = ?', (capsule_id,))
        cap = cur.fetchone()
        if not cap:
            return jsonify({'error': 'Capsule not found'}), 404
        cur.execute('SELECT * FROM contributions WHERE capsule_id = ? ORDER BY created_at ASC', (capsule_id,))
        contribs = cur.fetchall()
    unlock_date = datetime.strptime(cap[3], '%Y-%m-%d').date()
    is_unlocked = date.today() >= unlock_date
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(['id', 'contributor_name', 'created_at', 'type', 'has_message', 'has_ascii_art', 'has_image', 'message', 'ascii_art'])
    for c in contribs:
        has_message = bool(c[3])
        has_ascii = bool(c[4])
        has_image = bool(c[5])
        msg = c[3] if is_unlocked else ''
        art = c[4] if is_unlocked else ''
        writer.writerow([c[0], c[2], c[7], c[8], has_message, has_ascii, has_image, msg, art])
    data = buf.getvalue().encode('utf-8')
    mem = io.BytesIO(data)
    return send_file(mem, mimetype='text/csv; charset=utf-8', download_name=f'capsule_{capsule_id}.csv', as_attachment=True)


@app.route('/capsule/<int:capsule_id>/invites.csv')
@owner_required
def export_invites_csv(capsule_id):
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute('''
            SELECT email, status, invited_at, last_attempt_at, rsvp_at, contributed_at
            FROM invites WHERE capsule_id = ? ORDER BY invited_at DESC
        ''', (capsule_id,))
        rows = cur.fetchall()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(['email', 'status', 'invited_at', 'last_attempt_at', 'rsvp_at', 'contributed_at'])
    for r in rows:
        writer.writerow(list(r))
    data = buf.getvalue().encode('utf-8')
    mem = io.BytesIO(data)
    return send_file(mem, mimetype='text/csv; charset=utf-8', download_name=f'capsule_{capsule_id}_invites.csv', as_attachment=True)

@app.route('/capsule/<int:capsule_id>/owner', methods=['GET'])
@owner_required
def owner_dashboard(capsule_id):
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute('SELECT * FROM capsules WHERE id = ?', (capsule_id,))
        capsule = cur.fetchone()
        if not capsule:
            flash('Capsule not found!', 'error')
            return redirect(url_for('index'))
        cur.execute('SELECT * FROM contributions WHERE capsule_id = ? ORDER BY created_at DESC', (capsule_id,))
        contributions = cur.fetchall()
    cur.execute('SELECT id, email, status, invited_at, last_attempt_at, rsvp_at, contributed_at FROM invites WHERE capsule_id = ? ORDER BY invited_at DESC', (capsule_id,))
    invites = cur.fetchall()
    unlock_dt = datetime.strptime(capsule[3], '%Y-%m-%d').date()
    return render_template('owner_dashboard.html', capsule=capsule, contributions=contributions, invites=invites, unlock_date=unlock_dt)


@app.route('/capsule/<int:capsule_id>/owner/update', methods=['POST'])
@owner_required
def owner_update_settings(capsule_id):
    new_unlock = request.form.get('unlock_date', '').strip()
    new_slug = request.form.get('slug', '').strip().lower()
    new_hint = request.form.get('passphrase_hint', '').strip()
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        # Update unlock date only if in future and capsule not yet unlocked
        if new_unlock:
            try:
                unlock_dt = datetime.strptime(new_unlock, '%Y-%m-%d').date()
                if unlock_dt > date.today():
                    cur.execute('UPDATE capsules SET unlock_date = ? WHERE id = ?', (new_unlock, capsule_id))
                    flash('Unlock date updated.', 'success')
                else:
                    flash('Unlock date must be in the future.', 'warning')
            except Exception:
                flash('Invalid unlock date.', 'error')
        # Update slug (ensure unique)
        if new_slug:
            desired = slugify(new_slug)
            unique = ensure_unique_slug(conn, desired)
            cur.execute('UPDATE capsules SET slug = ? WHERE id = ?', (unique, capsule_id))
            flash('Share link updated.', 'success')
        # Update hint
        cur.execute('UPDATE capsules SET passphrase_hint = ? WHERE id = ?', (new_hint or None, capsule_id))
        conn.commit()
    return redirect(url_for('owner_dashboard', capsule_id=capsule_id))


@app.route('/capsule/<int:capsule_id>/contribution/<int:contrib_id>/delete', methods=['POST'])
@owner_required
def delete_contribution(capsule_id, contrib_id):
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute('DELETE FROM contributions WHERE id = ? AND capsule_id = ?', (contrib_id, capsule_id))
        conn.commit()
    flash('Contribution removed.', 'success')
    return redirect(url_for('owner_dashboard', capsule_id=capsule_id))


def send_email(to_email: str, subject: str, body: str) -> bool:
    host = os.getenv('SMTP_HOST')
    port = int(os.getenv('SMTP_PORT', '0') or 0)
    user = os.getenv('SMTP_USER')
    password = os.getenv('SMTP_PASS')
    from_addr = os.getenv('SMTP_FROM') or user
    use_tls = os.getenv('SMTP_USE_TLS', 'true').lower() == 'true'
    if not host or not port or not from_addr:
        app.logger.info('Email (dry-run) to %s: %s', to_email, subject)
        return False
    try:
        msg = EmailMessage()
        msg['From'] = from_addr
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.set_content(body)
        with smtplib.SMTP(host, port, timeout=10) as smtp:
            if use_tls:
                smtp.starttls()
            if user and password:
                smtp.login(user, password)
            smtp.send_message(msg)
        return True
    except Exception as e:
        app.logger.warning('Email send failed to %s: %s', to_email, e)
        return False


@app.route('/capsule/<int:capsule_id>/invite', methods=['POST'])
@limiter.limit("3 per minute; 30 per day")
def invite(capsule_id):
    # Owner-only: invite emails to contribute
    if not session.get(f'owner_auth_{capsule_id}'):
        flash('Owner login required.', 'error')
        return redirect(url_for('owner_login', capsule_id=capsule_id))
    emails_raw = request.form.get('emails', '')
    emails = [e.strip() for e in re.split(r'[\n,;\s]+', emails_raw) if e.strip()]
    # de-duplicate and validate
    unique_emails = []
    invalid_emails = []
    for e in emails:
        el = e.lower()
        if el not in unique_emails:
            if is_valid_email(el):
                unique_emails.append(el)
            else:
                invalid_emails.append(e)
    if invalid_emails:
        flash(f"Invalid emails ignored: {', '.join(invalid_emails[:5])}{'...' if len(invalid_emails) > 5 else ''}", 'warning')
    emails = unique_emails[:50]  # hard cap per batch
    if not emails:
        flash('Please enter at least one email address.', 'warning')
        return redirect(url_for('capsule_details', capsule_id=capsule_id))
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute('SELECT name, unlock_date FROM capsules WHERE id = ?', (capsule_id,))
        row = cur.fetchone()
        # per-capsule daily limit server-side (max 200/day)
        cur.execute("SELECT COUNT(*) FROM invites WHERE capsule_id = ? AND date(invited_at) = date('now')", (capsule_id,))
        today_count = cur.fetchone()[0]
        if today_count + len(emails) > 200:
            flash('Daily invite limit reached for this capsule.', 'error')
            return redirect(url_for('capsule_details', capsule_id=capsule_id))
        tokens = {}
        for email_addr in emails:
            tok = secrets.token_urlsafe(16)
            tokens[email_addr] = tok
            cur.execute('INSERT INTO invites (capsule_id, email, status, token) VALUES (?, ?, ?, ?)', (capsule_id, email_addr, 'pending', tok))
        conn.commit()
    # Attempt to send now (best-effort)
    for email_addr in emails:
        contribute_url = url_for('contribute', capsule_id=capsule_id, _external=True)
        accept_url = url_for('invite_rsvp', token=tokens[email_addr], d='accept', _external=True)
        decline_url = url_for('invite_rsvp', token=tokens[email_addr], d='decline', _external=True)
        subject = f"You're invited to contribute to {row[0]}'s Birthday Time Capsule"
        body = (
            f"We'd love your message!\n\nAdd your wishes: {contribute_url}\n"
            f"RSVP: Going {accept_url}  |  Can't {decline_url}\n"
            f"Unlocks on {row[1]}\n"
        )
        sent = send_email(email_addr, subject, body)
        try:
            with sqlite3.connect(DATABASE) as conn:
                conn.execute("UPDATE invites SET last_attempt_at = CURRENT_TIMESTAMP WHERE capsule_id = ? AND email = ?", (capsule_id, email_addr))
                conn.commit()
        except Exception:
            pass
    flash('Invites processed (check logs if email not configured).', 'success')
    return redirect(url_for('owner_dashboard', capsule_id=capsule_id))


@app.route('/capsule/<int:capsule_id>/invite/<int:invite_id>/resend', methods=['POST'])
@owner_required
def resend_invite(capsule_id, invite_id):
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute('SELECT email, status FROM invites WHERE id = ? AND capsule_id = ?', (invite_id, capsule_id))
        row = cur.fetchone()
        if not row:
            flash('Invite not found.', 'error')
            return redirect(url_for('owner_dashboard', capsule_id=capsule_id))
        email_addr, status = row
        if status == 'revoked':
            flash('This invite was revoked and cannot be resent.', 'warning')
            return redirect(url_for('owner_dashboard', capsule_id=capsule_id))
        cur.execute('SELECT name, unlock_date FROM capsules WHERE id = ?', (capsule_id,))
        cap = cur.fetchone()
    contribute_url = url_for('contribute', capsule_id=capsule_id, _external=True)
    subject = f"Reminder: contribute to {cap[0]}'s Time Capsule"
    body = f"We'd love your message: {contribute_url}\nUnlocks on {cap[1]}."
    send_email(email_addr, subject, body)
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('UPDATE invites SET last_attempt_at = CURRENT_TIMESTAMP WHERE id = ?', (invite_id,))
        conn.commit()
    flash('Invite resent (if email configured).', 'success')
    return redirect(url_for('owner_dashboard', capsule_id=capsule_id))


@app.route('/capsule/<int:capsule_id>/invite/<int:invite_id>/revoke', methods=['POST'])
@owner_required
def revoke_invite(capsule_id, invite_id):
    with sqlite3.connect(DATABASE) as conn:
        conn.execute("UPDATE invites SET status = 'revoked' WHERE id = ? AND capsule_id = ?", (invite_id, capsule_id))
        conn.commit()
    flash('Invite revoked.', 'success')
    return redirect(url_for('owner_dashboard', capsule_id=capsule_id))


@app.route('/invite/<token>/rsvp')
def invite_rsvp(token):
    decision = (request.args.get('d') or '').lower()
    if decision not in {'accept', 'decline'}:
        return jsonify({'error': 'invalid decision'}), 400
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute('SELECT id, capsule_id, status FROM invites WHERE token = ?', (token,))
        inv = cur.fetchone()
        if not inv:
            flash('Invite not found or expired.', 'error')
            return redirect(url_for('index'))
        if inv[2] == 'revoked':
            flash('This invite was revoked.', 'warning')
            return redirect(url_for('index'))
        new_status = 'accepted' if decision == 'accept' else 'declined'
        cur.execute("UPDATE invites SET status = ?, rsvp_at = CURRENT_TIMESTAMP WHERE id = ?", (new_status, inv[0]))
        conn.commit()
        if decision == 'accept':
            flash('Thanks for RSVPing! Add your message to the capsule.', 'success')
            return redirect(url_for('contribute', capsule_id=inv[1]))
        else:
            flash('RSVP recorded. You can still visit the capsule anytime.', 'info')
            return redirect(url_for('capsule_details', capsule_id=inv[1]))


@app.route('/capsule/<int:capsule_id>/verify_owner')
def verify_owner(capsule_id):
    token = request.args.get('token', '')
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute('SELECT owner_email, owner_verify_token FROM capsules WHERE id = ?', (capsule_id,))
        row = cur.fetchone()
        if not row:
            flash('Capsule not found.', 'error')
            return redirect(url_for('index'))
        if not token or token != (row[1] or ''):
            flash('Invalid verification link.', 'error')
            return redirect(url_for('capsule_details', capsule_id=capsule_id))
        cur.execute('UPDATE capsules SET owner_email_verified = 1, owner_verify_token = NULL WHERE id = ?', (capsule_id,))
        conn.commit()
    flash('Owner email verified.', 'success')
    return redirect(url_for('capsule_details', capsule_id=capsule_id))


@app.route('/capsule/<int:capsule_id>/owner_verify_resend', methods=['POST'])
@owner_required
def owner_verify_resend(capsule_id):
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute('SELECT owner_email, owner_email_verified FROM capsules WHERE id = ?', (capsule_id,))
        row = cur.fetchone()
        if not row or not row[0]:
            flash('No owner email set.', 'warning')
            return redirect(url_for('owner_dashboard', capsule_id=capsule_id))
        if row[1]:
            flash('Owner email already verified.', 'info')
            return redirect(url_for('owner_dashboard', capsule_id=capsule_id))
        tok = secrets.token_urlsafe(20)
        cur.execute('UPDATE capsules SET owner_verify_token = ? WHERE id = ?', (tok, capsule_id))
        conn.commit()
        email_addr = row[0]
    try:
        verify_url = url_for('verify_owner', capsule_id=capsule_id, token=tok, _external=True)
        send_email(email_addr, 'Verify your owner email', f'Click to verify: {verify_url}')
        flash('Verification email sent (if email is configured).', 'success')
    except Exception as e:
        app.logger.info('Owner verify email skipped: %s', e)
        flash('Failed to send verification email.', 'error')
    return redirect(url_for('owner_dashboard', capsule_id=capsule_id))


@app.route('/capsule/<int:capsule_id>/owner/delete', methods=['POST'])
@owner_required
def owner_delete_capsule(capsule_id):
    # Permanently delete capsule and its contributions and invites
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute('DELETE FROM contributions WHERE capsule_id = ?', (capsule_id,))
        cur.execute('DELETE FROM invites WHERE capsule_id = ?', (capsule_id,))
        cur.execute('DELETE FROM capsules WHERE id = ?', (capsule_id,))
        conn.commit()
    # Clear session flags for this capsule
    session.pop(f'owner_auth_{capsule_id}', None)
    session.pop(f'capsule_access_{capsule_id}', None)
    flash('Capsule deleted permanently.', 'success')
    return redirect(url_for('index'))


@app.route('/capsule/<int:capsule_id>/owner_magic_link', methods=['POST'])
def owner_magic_link(capsule_id):
    # Request a magic link to be sent to the verified owner email.
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute('SELECT owner_email, owner_email_verified FROM capsules WHERE id = ?', (capsule_id,))
        row = cur.fetchone()
        if not row or not row[0]:
            flash('Owner email not set.', 'error')
            return redirect(url_for('owner_login', capsule_id=capsule_id))
        if not row[1]:
            flash('Owner email is not verified.', 'warning')
            return redirect(url_for('owner_login', capsule_id=capsule_id))
        tok = secrets.token_urlsafe(22)
        expires = (datetime.utcnow() + timedelta(minutes=30)).isoformat()
        cur.execute('UPDATE capsules SET owner_magic_token = ?, owner_magic_expires = ? WHERE id = ?', (tok, expires, capsule_id))
        conn.commit()
        email_addr = row[0]
    try:
        link = url_for('owner_magic', capsule_id=capsule_id, token=tok, _external=True)
        send_email(email_addr, 'Your owner login link', f'Click to sign in: {link}\nThis link expires in 30 minutes.')
        flash('Magic link sent (if email configured).', 'success')
    except Exception as e:
        app.logger.info('Owner magic email skipped: %s', e)
        flash('Failed to send magic link.', 'error')
    return redirect(url_for('owner_login', capsule_id=capsule_id))


@app.route('/capsule/<int:capsule_id>/owner_magic')
def owner_magic(capsule_id):
    token = request.args.get('token', '')
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute('SELECT owner_magic_token, owner_magic_expires FROM capsules WHERE id = ?', (capsule_id,))
        row = cur.fetchone()
        if not row or not row[0] or not token or token != row[0]:
            flash('Invalid or used magic link.', 'error')
            return redirect(url_for('owner_login', capsule_id=capsule_id))
        # Check expiry
        try:
            exp = datetime.fromisoformat(row[1]) if row[1] else None
        except Exception:
            exp = None
        if not exp or datetime.utcnow() > exp:
            flash('Magic link expired. Request a new one.', 'warning')
            return redirect(url_for('owner_login', capsule_id=capsule_id))
        # Consume token
        cur.execute('UPDATE capsules SET owner_magic_token = NULL, owner_magic_expires = NULL WHERE id = ?', (capsule_id,))
        conn.commit()
    session[f'owner_auth_{capsule_id}'] = True
    flash('Signed in with magic link.', 'success')
    return redirect(url_for('owner_dashboard', capsule_id=capsule_id))


@app.route('/tasks/send_reminders')
def task_send_reminders():
    token = request.args.get('token') or request.headers.get('X-Task-Token')
    expected = os.getenv('TASK_TOKEN')
    if not expected or token != expected:
        return jsonify({'error': 'forbidden'}), 403
    count = send_unlock_reminders()
    return jsonify({'attempted': count})


# Error handlers
@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def server_error(e):
    app.logger.exception('Server error: %s', e)
    return render_template('500.html'), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    return render_template('429.html'), 429

if __name__ == '__main__':
    init_db()
    # Start scheduler only in the reloader main process
    if not app.debug or os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
        start_scheduler()
    debug = os.getenv('FLASK_DEBUG', 'true').lower() == 'true'
    host = os.getenv('FLASK_HOST', '127.0.0.1')
    port = int(os.getenv('FLASK_PORT', '5000'))
    app.run(debug=debug, host=host, port=port)