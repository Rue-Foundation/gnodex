import os

def path_to(file):
    return os.path.abspath(os.path.join(os.path.dirname(__file__), file))