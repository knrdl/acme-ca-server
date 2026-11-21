from ipaddress import IPv4Address, IPv6Address

from pydantic import IPvAnyAddress, TypeAdapter

_ip_address_adapter: TypeAdapter[IPv4Address | IPv6Address] = TypeAdapter(IPvAnyAddress)


def parse_ip(value: str) -> IPv4Address | IPv6Address:
    """Parse and normalize an IPv4/IPv6 address using pydantic (raises pydantic.ValidationError if invalid)."""
    return _ip_address_adapter.validate_python(value)
