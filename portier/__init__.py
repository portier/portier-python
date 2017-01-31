import pkg_resources
from .client import discover_keys, get_verified_email


# Module version, as defined in PEP-0396.
__version__ = pkg_resources.get_distribution('portier-python').version

# Public API
__all__ = (
    'discover_keys',
    'get_verified_email'
)
