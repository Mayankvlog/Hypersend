# Backend package
import os, sys

# If running under pytest (module already imported) or tests are loading the
# backend package, ensure we have a dummy MongoDB URI so config initialization
# does not raise an error during import-time collection.
if os.getenv("PYTEST_CURRENT_TEST") or "pytest" in sys.modules:
    os.environ.setdefault(
        "MONGODB_URI",
        "mongodb+srv://user:pass@cluster.mongodb.net/test?retryWrites=true&w=majority",
    )
    os.environ.setdefault("MONGODB_ATLAS_ENABLED", "true")
    # also provide a dummy database name during tests so Settings init succeeds
    os.environ.setdefault("DATABASE_NAME", "test")

from . import routes
