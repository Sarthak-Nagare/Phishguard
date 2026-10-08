import sys
import os

# Add root project directory to sys.path for Vercel serverless runtime
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app

# Vercel serverless function entrypoint
