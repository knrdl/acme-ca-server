# this file can be overwritten to provide a custom ca implementation
# the methods sign_csr() and revoke_cert() must be implemented with matching function signatures
# set env var CA_ENABLED=False when providing a custom ca implementation

import asyncio
from datetime import datetime, timezone

from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

from .. import db
from ..acme.certificate.service import SerialNumberConverter
from ..config import settings

from .model import SignedCertInfo


async def sign_csr(
    csr: x509.CertificateSigningRequest, subject_domain: str, san_domains: list[str]
) -> SignedCertInfo:
    """
    csr: the parsed csr object
    subject_domain: the main requested domain name
    san_domains: the alternative (additional) requested domain names
    """
    if not settings.ca.enabled:
        raise Exception(  # pylint: disable=broad-exception-raised
            'internal ca is not enabled (env var CA_ENABLED)! Please provide a custom ca implementation'
        )

    ca_cert, ca_key = await load_active_ca()

    cert, cert_chain_pem = await asyncio.to_thread(generate_cert_sync, ca_key=ca_key, ca_cert=ca_cert, csr=csr, subject_domain=subject_domain, san_domains=san_domains)

    return SignedCertInfo(cert=cert, cert_chain_pem=cert_chain_pem)


async def revoke_cert(
    serial_number: str, revocations: set[tuple[str, datetime]]  # pylint: disable=unused-argument
) -> None:
    if not settings.ca.enabled:
        raise Exception(  # pylint: disable=broad-exception-raised
            'internal ca is not enabled (env var CA_ENABLED)! Please provide a custom ca implementation'
        )
    ca_cert, ca_key = await load_active_ca()
    _, crl_pem = await asyncio.to_thread(
        build_crl_sync, ca_key=ca_key, ca_cert=ca_cert, revocations=revocations
    )
    async with db.transaction() as sql:
        await sql.exec("""update cas set crl_pem = $1 where active = true""", crl_pem)


async def load_active_ca():
    async with db.transaction(readonly=True) as sql:
        cert_pem, key_pem_enc = await sql.record("""select cert_pem, key_pem_enc from cas where active = true""")
    return await asyncio.to_thread(load_ca_sync, cert_pem=cert_pem, key_pem_enc=key_pem_enc)


def load_ca_sync(*, cert_pem, key_pem_enc):
    f = Fernet(settings.ca.encryption_key.get_secret_value())
    key_pem = f.decrypt(key_pem_enc)
    ca_key = serialization.load_pem_private_key(key_pem, None)
    ca_cert = x509.load_pem_x509_certificate(cert_pem.encode(), None)
    return ca_cert, ca_key


def generate_cert_sync(*, ca_key: PrivateKeyTypes, ca_cert: x509.Certificate, csr: x509.CertificateSigningRequest, subject_domain: str, san_domains: list[str]):
    ca_id = SerialNumberConverter.int2hex(ca_cert.serial_number)

    cert_builder = (
        x509.CertificateBuilder(
            issuer_name=ca_cert.subject,
            subject_name=x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, subject_domain)]),
            serial_number=x509.random_serial_number(),
            not_valid_before=datetime.now(timezone.utc),
            not_valid_after=datetime.now(timezone.utc) + settings.ca.cert_lifetime,
            public_key=csr.public_key(),
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.CRLDistributionPoints(
                distribution_points=[
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier(str(settings.external_url).removesuffix('/') + f'/ca/{ca_id}/crl')],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                ]
            ),
            critical=False,
        )
        .add_extension(x509.SubjectAlternativeName(general_names=[x509.DNSName(domain) for domain in san_domains]), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage(usages=[x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH, x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    )

    cert = cert_builder.sign(private_key=ca_key, algorithm=hashes.SHA512())

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
    cert_chain_pem = (cert_pem + ca_cert_pem).decode()

    return cert, cert_chain_pem


def build_crl_sync(
    *,
    ca_key: PrivateKeyTypes,
    ca_cert: x509.Certificate,
    revocations: set[tuple[str, datetime]],
):
    now = datetime.utcnow()
    builder = x509.CertificateRevocationListBuilder(
        last_update=now,
        next_update=now + settings.ca.crl_lifetime,
        issuer_name=ca_cert.subject,
    )
    for serial_number, revoked_at in revocations:
        revoked_cert = x509.RevokedCertificateBuilder().serial_number(SerialNumberConverter.hex2int(serial_number)).revocation_date(revoked_at).build()
        builder = builder.add_revoked_certificate(revoked_cert)
    crl = builder.sign(private_key=ca_key, algorithm=hashes.SHA512())
    crl_pem = crl.public_bytes(encoding=serialization.Encoding.PEM).decode()
    return crl, crl_pem
