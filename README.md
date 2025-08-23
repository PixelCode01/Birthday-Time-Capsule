# Birthday Time Capsule

A digital birthday time capsule application built with Python Flask that allows friends and family to create surprise birthday messages that unlock on future milestone birthdays.

## Features

- **Create Time Capsules**: Set up birthday capsules with future unlock dates
- **Collect Contributions**: Friends can add text messages, ASCII art, and images
- **Cryptographic Security**: Messages are encrypted until the unlock date
- **Future Self Letters**: Personal messages from past to future self
- **Birthday Reveal**: Animated unlock experience with birthday surprises
- **Milestone Birthdays**: Lock capsules until significant birthday milestones

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run the application:
```bash
python app.py
```

3. Open your browser and go to `http://localhost:5000`

4. Optional: copy environment template and adjust settings
```bash
cp .env.example .env
# edit .env to set SECRET_KEY, SMTP, etc.
```

## How It Works

1. **Create a Capsule**: Set the birthday person's name, birthdate, unlock date, and a secret passphrase
2. **Add Future Self Letter**: Write a message to the future self
3. **Share Capsule ID**: Friends use the ID to find and contribute to the capsule
4. **Collect Wishes**: Contributors add messages, ASCII art doodles, and images
5. **Wait for Unlock Date**: The capsule remains sealed until the specified date
6. **Birthday Reveal**: On the unlock date, enter the passphrase to reveal all messages with animations

## Security

- Messages are encrypted using the Fernet symmetric encryption
- Encryption key is derived from birthdate + passphrase using PBKDF2
- Capsules cannot be unlocked before the specified date
- Database stores only encrypted data

Additional hardening:
- Strict security headers via Talisman (CSP, HSTS when FORCE_HTTPS=true)
- CSRF protection enabled site-wide
- Configurable rate limiting (default in-memory; set RATELIMIT_STORAGE_URI for production)
- Session cookies use HttpOnly and SameSite; set SESSION_COOKIE_SECURE=true for HTTPS

## File Structure

```
Birthday Time Capsule/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── templates/            # HTML templates
│   ├── base.html         # Base template with styling
│   ├── index.html        # Home page
│   ├── create_capsule.html
│   ├── find_capsule.html
│   ├── capsule_details.html
│   ├── contribute.html
│   ├── unlock.html
│   └── reveal.html       # Birthday surprise page
└── time_capsule.db      # SQLite database (auto-created)
```

## Database Schema

**Capsules Table:**
- id (Primary Key)
- name (Birthday person's name)
- birthdate
- unlock_date
- encrypted_data (JSON with future letter and metadata)
- created_at

**Contributions Table:**
- id (Primary Key)
- capsule_id (Foreign Key)
- contributor_name
- message
- ascii_art
- image_data (Base64 encoded)
- created_at

## Usage Examples

### Creating a Capsule
1. Go to the home page
2. Click "Create New Capsule"
3. Fill in details for a 25th birthday milestone
4. Write a letter to future self
5. Share the generated Capsule ID

### Adding Contributions
1. Use "Find Capsule" with the shared ID
2. Click "Add Your Contribution"
3. Enter your name and birthday message
4. Optionally add ASCII art or upload an image
5. Submit your contribution

### Unlocking on Birthday
1. On or after the unlock date, visit the capsule
2. Click "Unlock Time Capsule"
3. Enter the secret passphrase
4. Enjoy the animated birthday reveal with all messages

## Technical Details

- **Encryption**: Uses Fernet (AES 128) with PBKDF2 key derivation
- **Database**: SQLite for simplicity and portability
- **Frontend**: Bootstrap 5 with custom CSS animations
- **File Upload**: Base64 encoding for small images
- **Date Validation**: Prevents unlocking before specified date

### Operational notes
- Health check: GET `/health` returns `{ "status": "ok" }`
- Robots: `/robots.txt`; Sitemap: `/sitemap.xml`
- Export: `/capsule/<id>/export.json` and `/capsule/<id>/export.zip`
- ICS calendar: `/capsule/<id>/ics`
- QR code for contributions: `/capsule/<id>/qr`

### Configuration via .env
See `.env.example` for common settings:
- SECRET_KEY, FLASK_HOST, FLASK_PORT, FLASK_DEBUG
- FORCE_HTTPS, TRUST_PROXY, SESSION_COOKIE_SECURE
- DATABASE_URL (default `time_capsule.db`)
- SMTP_* (for invites/notifications)
- RATELIMIT_STORAGE_URI (e.g., Redis) for production scale

This application creates a unique birthday experience by combining the nostalgia of time capsules with modern web technology and security.
