import os
from dotenv import load_dotenv
from app import app as application, init_db, start_scheduler
load_dotenv()
try:
    init_db()
    # Start scheduler in WSGI context once
    if os.getenv('ENABLE_SCHEDULER', 'true').lower() == 'true':
        start_scheduler()
except Exception as e:
    # Avoid crashing import on hosts that import at build time
    try:
        application.logger.warning('WSGI init failed: %s', e)
    except Exception:
        pass
