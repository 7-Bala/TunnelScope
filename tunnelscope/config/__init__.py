"""T-120: read IPsec configuration files (offline, Nipper-style) into one normalised crypto model."""
from .parse import parse_config, parse_file

__all__ = ["parse_config", "parse_file"]
