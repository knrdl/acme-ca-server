import asyncio

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi import status

from ..exceptions import ACMEException


class SerialNumberConverter:
    @staticmethod
    def int2hex(number: int):
        return hex(number)[2:].upper()

    @staticmethod
    def hex2int(number: str):
        return int(number, 16)


async def check_csr(csr_der: bytes, ordered_domains: list[str], new_nonce: str | None = None):
    """
    check csr and return the contained identifiers.
    Each identifier is returned as a (type, value) pair, where the type comes from the X.509 SAN
    extension (dNSName/iPAddress) or the common name - it is never inferred by parsing the value.
    """
    csr = await asyncio.to_thread(x509.load_der_x509_csr, csr_der)
    csr_pem_job = asyncio.to_thread(csr.public_bytes, serialization.Encoding.PEM)

    if not csr.is_signature_valid:
        raise ACMEException(status_code=status.HTTP_400_BAD_REQUEST, exctype='badCSR', detail='invalid signature', new_nonce=new_nonce)

    san_extension = csr.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    sans = [('dns', san.lower()) for san in san_extension.get_values_for_type(x509.DNSName)]  # type: ignore[attr-defined]
    sans += [('ip', str(ip).lower()) for ip in san_extension.get_values_for_type(x509.IPAddress)]  # type: ignore[attr-defined]
    csr_domains = {value for _, value in sans}
    subject_candidates = csr.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    if subject_candidates:
        subject_value = str(subject_candidates[0].value).lower()
        subject = ('dns', subject_value)
        csr_domains.add(subject_value)
    elif not sans:
        raise ACMEException(status_code=status.HTTP_400_BAD_REQUEST, exctype='badCSR', detail='subject and SANs cannot be both empty', new_nonce=new_nonce)
    else:
        subject = sans[0]

    if csr_domains != set(ordered_domains):
        raise ACMEException(status_code=status.HTTP_400_BAD_REQUEST, exctype='badCSR', detail='domains in CSR does not match validated domains in ACME order', new_nonce=new_nonce)

    csr_pem: str = (await csr_pem_job).decode()
    return csr, csr_pem, subject, sans


async def parse_cert(cert_der: bytes):
    cert = await asyncio.to_thread(x509.load_der_x509_certificate, cert_der)
    return cert
