import sys
import os

# Add the project root to sys.path so that imports like "from engine.params import ..." work
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
