import json
from pathlib import Path
from typing import List, Dict


def load_json(file_path: str) -> List[Dict]:
    """Load a JSON file and return its contents"""
    path = Path(file_path)
    
    if not path.exists():
        raise FileNotFoundError(f"{file_path} not found.")
    
    with open(path, "r") as f:
        return json.load(f)


def load_identities(file_path: str) -> List[Dict]:
    """Alias for load_json for backward compatibility"""
    return load_json(file_path)
