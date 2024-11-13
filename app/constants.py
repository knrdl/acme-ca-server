from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent

MIGRATIONS_PATH = PROJECT_ROOT / 'app' / 'db' / 'migrations'

WEB_TEMPLATES_PATH = PROJECT_ROOT / 'app' / 'web' / 'templates'