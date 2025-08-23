# Birthday Time Capsule

A small Flask app to collect birthday messages in a “time capsule.” Create a capsule, share a link, let friends add notes/photos, and unlock everything on the big day.

## What it does

- Create a capsule with a name and unlock date
- Share a link or QR so friends can contribute
- Messages stay sealed (encrypted) until unlock
- Optional owner/access PINs and a simple owner view
- Uses a local SQLite database (`time_capsule.db`)

## Quick start

1) Install deps

```
pip install -r requirements.txt
```

2) Run it

```
python app.py
```

3) Open http://localhost:5000

## How to use

1) Create a capsule and set the unlock date
2) Share the capsule page (or its slug/QR) with friends
3) Friends add messages (text, ASCII art, small images)
4) On/after the date, unlock to reveal everything together

## Notes

- Health check at `/health` (handy for deploys)
- Data is stored locally in `time_capsule.db`
- Deploying? See `README_DEPLOY.md` and `Procfile`/`wsgi.py`
