"""
conftest.py — shared fixtures for all AppSec lab tests
"""
import pytest
import sqlite3
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'workspace'))


@pytest.fixture
def app():
    """Create a test Flask app with an in-memory database."""
    import app as student_app
    student_app.app.config["TESTING"] = True
    student_app.app.config["DATABASE"] = ":memory:"
    
    # Create an app context that persists for the test
    ctx = student_app.app.app_context()
    ctx.push()
    student_app.init_db()
    
    yield student_app.app
    
    # Clean up the context
    ctx.pop()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def db(app):
    import app as student_app
    with app.app_context():
        conn = student_app.get_db()
        yield conn
