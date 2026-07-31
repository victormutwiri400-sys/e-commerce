import sys
import os

# Add your project directory to the Python path
project_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_dir)

# Import your Flask application instance (change 'commerce' if your main file has a different name)
from commerce import app as application