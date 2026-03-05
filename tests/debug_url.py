import os
os.environ['REDIS_HOST'] = 'redis'
os.environ['REDIS_PORT'] = '6379'
os.environ['REDIS_PASSWORD'] = 'testpass'
os.environ['REDIS_DB'] = '1'
os.environ['MONGODB_URI'] = 'mongodb+srv://test:test@cluster.mongodb.net/test'
os.environ['DATABASE_NAME'] = 'test'
os.environ['JWT_SECRET_KEY'] = 'test-secret-key'

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Import and reload config
import importlib
from backend import config
importlib.reload(config)
settings = config.Settings()

# Parse URL safely to check components without exposing credentials
from urllib.parse import urlparse
parsed_url = urlparse(settings.REDIS_URL)

print(f'Scheme: {parsed_url.scheme}')
print(f'Hostname: {parsed_url.hostname}')
print(f'Port: {parsed_url.port}')
print(f'Database: {parsed_url.path.lstrip("/")}')

# Verify expected components
assert parsed_url.scheme == 'redis', f"Expected redis scheme, got {parsed_url.scheme}"
assert parsed_url.hostname == 'redis', f"Expected redis hostname, got {parsed_url.hostname}"
assert parsed_url.port == 6379, f"Expected port 6379, got {parsed_url.port}"
assert parsed_url.path.lstrip("/") == "1", f"Expected database 1, got {parsed_url.path.lstrip('/')}"
print(f'Test passes: {"redis://redis:6379/1" in settings.REDIS_URL}')
