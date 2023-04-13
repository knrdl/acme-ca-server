from cryptography import x509
from dataclasses import dataclass


@dataclass
class SignedCertInfo:
    cert: x509.Certificate
    cert_chain_pem: str
