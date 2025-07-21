import yaml
from typing import Dict, Any

def load_config(config_path: str = 'rabbitRecon.conf') -> Dict[str, Any]:
    """Load configuration from YAML file"""
    try:
        with open(config_path) as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid config file: {str(e)}")
