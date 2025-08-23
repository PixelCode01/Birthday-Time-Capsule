# Deploying Birthday Time Capsule (Free)

This app is a single-file Flask app with SQLite. Below are simple, free options to deploy.

Quick facts:
- WSGI entrypoint: `wsgi:application`
- HTTP health check: `/health` returns `{ "status": "ok" }`
- Uses SQLite by default (`DATABASE_URL=time_capsule.db`)
- Background reminders via APScheduler; can be disabled via `ENABLE_SCHEDULER=false` and triggered via `/tasks/send_reminders?token=...`

## Option A: PythonAnywhere (free tier)
Best for always-on free hosting with WSGI.

1) Fork/clone your repo to GitHub.
2) Create a PythonAnywhere account and log in.
3) On the Dashboard → "Web" → "Add a new web app" → Manual configuration → Python 3.x.
4) In the web app config:
   - Code: point to your repo (use "Files" to `git clone` in your home dir).
   - WSGI configuration file: set it to import `wsgi:application` from your project folder. Example:
     
     ```python
     import sys, os
     project_dir = '/home/<your-username>/Birthday-Time-Capsule'
     if project_dir not in sys.path:
         sys.path.insert(0, project_dir)
     os.chdir(project_dir)
     from wsgi import application
     ```
   - Virtualenv: create one inside your PA home (e.g., `~/.venvs/btc`) and set it in the Web tab.
   - Environment variables: add from `.env.example` (at least `SECRET_KEY`).
5) Open a Bash console in PythonAnywhere, then:
   - `pip install -r requirements.txt`
   - Optionally migrate/initialize DB on first run: it auto-inits.
6) Reload the web app from the Web tab.

Notes:
- SQLite file lives alongside code. Back it up by downloading `time_capsule.db` from the Files tab.
- To avoid duplicate schedulers, set `ENABLE_SCHEDULER=true` and keep a single worker (default on PA).

## Option B: Render free web service
Great for quick demos. Persistent free tier may sleep.

1) Push to GitHub.
2) On Render → "New +" → Web Service → Connect repo.
3) Runtime: Python 3.11 or 3.12.
4) Build Command: `pip install -r requirements.txt`
5) Start Command: `gunicorn -w 2 -k gthread -t 120 -b 0.0.0.0:${PORT} wsgi:application`
6) Add Environment:
   - `SECRET_KEY` — set to a random long value
   - `FLASK_DEBUG=false`
   - `FORCE_HTTPS=true`
   - `TRUST_PROXY=true`
   - `SESSION_COOKIE_SECURE=true`
   - `ENABLE_SCHEDULER=false` (Render may spawn multiple dynos)
7) Deploy. Visit the URL to confirm `/health` is OK.

Persistence:
- SQLite on ephemeral disk will reset on redeploys. Consider Render Disks (paid) or switch to a managed DB.

## Option C: Fly.io (free allowance varies)
1) Install `flyctl` and run `fly launch` in the project root.
2) Choose a Python image. Add a volume for persistent SQLite or switch to Postgres.
3) Set env vars (`fly secrets set SECRET_KEY=...`).
4) `fly deploy`.

## Option D: Railway (free tier changes)
- Create a Python service, set Build + Start commands same as Render.
- Use a Volume for persistent SQLite or Railway Postgres plugin.

## Local run
- Copy `.env.example` to `.env`, edit values.
- `pip install -r requirements.txt`
- `python app.py` then open `http://localhost:5000`.

## Email (optional)
Set SMTP_* env vars if you want invite/notification emails to send. If not set, logs will show a dry-run and app works without email.

## Cron alternative for reminders
If your host doesn't allow long-running schedulers, disable with `ENABLE_SCHEDULER=false` and call:
- `GET /tasks/send_reminders?token=<TASK_TOKEN>`
You can wire this to a free cron service like cron-job.org.

## Security checklist
- Set a strong `SECRET_KEY` and `SESSION_COOKIE_SECURE=true` behind HTTPS.
- Use `TRUST_PROXY=true` on proxying hosts.
- Keep `FLASK_DEBUG=false` in production.

