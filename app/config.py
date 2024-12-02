from datetime import timedelta
import sys
from typing import Any, Literal, Optional, Pattern
from pathlib import Path

from pydantic import AnyHttpUrl, EmailStr, PostgresDsn, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from logger import logger


class WebSettings(BaseSettings):
    enabled: bool = True
    enable_public_log: bool = False
    app_title: str = 'ACME CA Server'
    app_description: str = 'Self hosted ACME CA Server'
    model_config = SettingsConfigDict(env_prefix='web_')


class CaSettings(BaseSettings):
    enabled: bool = True
    cert_lifetime: timedelta = timedelta(days=60)
    crl_lifetime: timedelta = timedelta(days=7)
    encryption_key: Optional[SecretStr] = None  # encryption of private keys in database
    import_dir: Path = '/import'

    model_config = SettingsConfigDict(env_prefix='ca_')

    @model_validator(mode='after')
    def valid_check(self) -> 'CaSettings':
        if self.enabled:
            if not self.encryption_key:
                from cryptography.fernet import Fernet  # pylint: disable=import-outside-toplevel

                logger.fatal('Env Var ca_encryption_key is missing, use this freshly generated key: %s', Fernet.generate_key().decode())
                sys.exit(1)
            if self.cert_lifetime.days < 1:
                raise ValueError('Cert lifetime for internal CA must be at least one day, not: ' + str(self.cert_lifetime))
            if self.crl_lifetime.days < 1:
                raise ValueError('CRL lifetime for internal CA must be at least one day, not: ' + str(self.crl_lifetime))
        return self


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

    model_config = SettingsConfigDict(env_prefix='mail_')

    @model_validator(mode='before')
    @classmethod
    def sanitize_values(cls, values: Any) -> Any:
        if 'warn_before_cert_expires' in values:  # not in values if default value
            if (values['warn_before_cert_expires'] or '').lower().strip() in ('', 'false', '0', '-1'):
                values['warn_before_cert_expires'] = False
        return values

    @model_validator(mode='after')
    def valid_check(self) -> 'MailSettings':
        if self.enabled and (not self.host or not self.sender):
            raise ValueError('Mail parameters (mail_host, mail_sender) are missing as SMTP is enabled')
        if (self.username and not self.password) or (not self.username and self.password):
            raise ValueError('Either no mail auth must be specified or username and password must be provided')
        if self.enabled and not self.port:
            self.port = {'tls': 465, 'starttls': 587, 'plain': 25}[self.encryption]
        return self


class AcmeSettings(BaseSettings):
    terms_of_service_url: AnyHttpUrl | None = None
    mail_target_regex: Pattern = r'[^@]+@[^@]+\.[^@]+'
    target_domain_regex: Pattern = r'[^\*]+\.[^\.]+'  # disallow wildcard

    model_config = SettingsConfigDict(env_prefix='acme_')


class Settings(BaseSettings):
    external_url: AnyHttpUrl
    db_dsn: PostgresDsn
    acme: AcmeSettings = AcmeSettings()
    ca: CaSettings = CaSettings()
    mail: MailSettings = MailSettings()
    web: WebSettings = WebSettings()

    @model_validator(mode='before')
    @classmethod
    def sanitize_values(cls, data: Any) -> Any:
        if 'external_url' in data and not data['external_url'].endswith('/'):
            data['external_url'] += '/'
        return data

    @model_validator(mode='after')
    def valid_check(self) -> 'Settings':
        if self.external_url.scheme != 'https':
            logger.warning('Env Var "external_url" is not HTTPS. This is insecure!')
        if self.mail.warn_before_cert_expires and self.ca.enabled and self.mail.enabled:
            if self.mail.warn_before_cert_expires >= self.ca.cert_lifetime:
                raise ValueError('Env var web_warn_before_cert_expires cannot be greater than ca_cert_lifetime')
            if self.mail.warn_before_cert_expires.days > self.ca.cert_lifetime.days / 2:
                logger.warning('Env var mail_warn_before_cert_expires should be more than half of the cert lifetime')
        return self


settings = Settings()


logger.info('Settings: %s', settings.model_dump())
