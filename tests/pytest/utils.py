from ipaddress import ip_address

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa


def build_csr(names: list[str]) -> x509.CertificateSigningRequest:
    """Returns a certificate signing request containing the given names.

    The first given name is used as the common name. Any further names are used as subject alternative names.
    The signing request is signed using a freshly generated RSA private key with 2048 bit length and SHA256 hashing.
    """
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, names[0])]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name) for name in names[1:]]), critical=False)
        .sign(rsa.generate_private_key(65537, 2048), hashes.SHA256())
    )


def build_ip_csr(ip_addresses: list[str]) -> x509.CertificateSigningRequest:
    """Returns a certificate signing request containing the given IP addresses as subject alternative names.

    No common name is set (an IP address must not be used as the common name, see RFC 5280),
    so the subject is left empty.
    """
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([]))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ip_address(ip)) for ip in ip_addresses]), critical=False)
        .sign(rsa.generate_private_key(65537, 2048), hashes.SHA256())
    )


def build_mixed_csr(domain_names: list[str], ip_addresses: list[str]) -> x509.CertificateSigningRequest:
    """Returns a certificate signing request containing both domain names and IP addresses.

    The first given domain name is used as the common name; all domain names and IP addresses are added as SANs.
    """
    general_names = [x509.DNSName(name) for name in domain_names] + [x509.IPAddress(ip_address(ip)) for ip in ip_addresses]
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, domain_names[0])]))
        .add_extension(x509.SubjectAlternativeName(general_names), critical=False)
        .sign(rsa.generate_private_key(65537, 2048), hashes.SHA256())
    )
