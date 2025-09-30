import os

SERVER_MODE = True
DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'pgadmin-data'))
LOG_FILE = os.path.join(DATA_DIR, 'pgadmin4.log')
SQLITE_PATH = os.path.join(DATA_DIR, 'pgadmin4.db')
SESSION_DB_PATH = os.path.join(DATA_DIR, 'sessions')
STORAGE_DIR = os.path.join(DATA_DIR, 'storage')
