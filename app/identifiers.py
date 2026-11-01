from ipaddress import ip_address
from typing import Literal


def is_ip(value: str) -> bool:
    """Return True if the given identifier value is a valid IP address (IPv4 or IPv6)."""
    try:
        ip_address(value)
    except ValueError:
        return False
    return True


def identifier_type(value: str) -> Literal['dns', 'ip']:
    """Return the ACME identifier type ('dns' or 'ip') for the given identifier value."""
    return 'ip' if is_ip(value) else 'dns'
