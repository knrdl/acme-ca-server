from dataclasses import dataclass

from cryptography import x509


@dataclass
class SignedCertInfo:
    cert: x509.Certificate
    cert_chain_pem: str
