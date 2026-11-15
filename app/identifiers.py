from ipaddress import IPv4Address, IPv6Address
from typing import Literal

from pydantic import IPvAnyAddress, TypeAdapter, ValidationError

_ip_address_adapter: TypeAdapter[IPv4Address | IPv6Address] = TypeAdapter(IPvAnyAddress)


def parse_ip(value: str) -> IPv4Address | IPv6Address:
    """Parse and normalize an IPv4/IPv6 address (raises pydantic.ValidationError if invalid)."""
    return _ip_address_adapter.validate_python(value)


def is_ip(value: str) -> bool:
    """Return True if the given identifier value is a valid IP address (IPv4 or IPv6)."""
    try:
        parse_ip(value)
    except ValidationError:
        return False
    return True


def identifier_type(value: str) -> Literal['dns', 'ip']:
    """Return the ACME identifier type ('dns' or 'ip') for the given identifier value."""
    return 'ip' if is_ip(value) else 'dns'
