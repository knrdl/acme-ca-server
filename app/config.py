from datetime import timedelta
from typing import Any, Literal, Optional, Pattern

from logger import logger
from pydantic import AnyHttpUrl, BaseSettings, EmailStr, PostgresDsn, SecretStr, root_validator


class WebSettings(BaseSettings):
    enabled: bool = True
    enable_public_log: bool = False
    app_title: str = 'ACME CA Server'
    app_description: str = 'Self hosted ACME CA Server'

    class Config:
        env_prefix = 'web_'


class CaSettings(BaseSettings):
    enabled: bool = True
    cert_lifetime: timedelta = timedelta(days=60)
    crl_lifetime: timedelta = timedelta(days=7)
    # encryption of private keys in database
    encryption_key: Optional[SecretStr]

    class Config:
        env_prefix = 'ca_'

    @root_validator
    def valid_check(cls, values: dict[str, Any]) -> dict[str, Any]:
        if values['enabled']:
            if not values['encryption_key']:
                from cryptography.fernet import Fernet
                raise Exception(
                    'Env Var ca_encryption_key is missing, use this freshly generated key: ' + Fernet.generate_key().decode())
            if values['cert_lifetime'].days < 1:
                raise Exception(
                    'Cert lifetime for internal CA must be at least one day, not: ' + str(values['cert_lifetime']))
            if values['crl_lifetime'].days < 1:
                raise Exception(
                    'CRL lifetime for internal CA must be at least one day, not: ' + str(values['crl_lifetime']))
        return values


class MailSettings(BaseSettings):
    enabled: bool = False
    host: Optional[str] = None
    port: Optional[int] = None
    username: Optional[str] = None
    password: Optional[SecretStr] = None
    encryption: Literal['tls', 'starttls', 'plain'] = 'tls'
    sender: Optional[EmailStr] = None
    notify_on_account_creation: bool = True
    warn_before_cert_expires: timedelta | Literal[False] = timedelta(days=20)
    notify_when_cert_expired: bool = True

    class Config:
        env_prefix = 'mail_'

    @root_validator(pre=True)
    def sanitize_values(cls, values):
        if 'warn_before_cert_expires' in values:  # not in values if default value
            if (values.get('warn_before_cert_expires') or '').lower().strip() in ('', 'false', '0', '-1'):
                values['warn_before_cert_expires'] = False
        return values

    @root_validator(pre=False)
    def valid_check(cls, values: dict[str, Any]) -> dict[str, Any]:
        if values['enabled'] and (not values.get('host') or not values.get('sender')):
            raise Exception(
                'Mail parameters (mail_host, mail_sender) are missing as SMTP is enabled')
        if (values.get('username') and not values.get('password')) or (not values.get('username') and values.get('password')):
            raise Exception(
                'Either no mail auth must be specifid or username and password must be provided')
        if values['enabled'] and not values.get('port'):
            values['port'] = {
                'tls': 465, 'starttls': 587, 'plain': 25
            }[values['encryption']]
        return values


class AcmeSettings(BaseSettings):
    terms_of_service_url: AnyHttpUrl = None
    mail_target_regex: Pattern = r'[^@]+@[^@]+\.[^@]+'
    target_domain_regex: Pattern = r'[^\*]+\.[^\.]+'  # disallow wildcard

    class Config:
        env_prefix = 'acme_'


class Settings(BaseSettings):
    external_url: AnyHttpUrl
    db_dsn: PostgresDsn
    acme: AcmeSettings = AcmeSettings()
    ca: CaSettings = CaSettings()
    mail: MailSettings = MailSettings()
    web: WebSettings = WebSettings()


settings = Settings()


logger.info(f'Settings: {settings.dict()}')

if settings.external_url.scheme != 'https':
    logger.warn('Env Var "external_url" is not HTTPS. This is insecure!')

if settings.mail.warn_before_cert_expires and settings.ca.enabled and settings.mail.enabled:
    if settings.mail.warn_before_cert_expires >= settings.ca.cert_lifetime:
        raise Exception(
            'Env var web_warn_before_cert_expires cannot be greater than ca_cert_lifetime')
    if settings.mail.warn_before_cert_expires.days > settings.ca.cert_lifetime.days / 2:
        logger.warn(
            'Env var mail_warn_before_cert_expires should be more than half of the cert lifetime')
