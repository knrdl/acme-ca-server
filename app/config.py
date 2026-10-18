import re
import sys
from datetime import timedelta
from pathlib import Path
from re import Pattern
from typing import Annotated, Any, Literal

from logger import logger
from pydantic import AnyHttpUrl, EmailStr, PostgresDsn, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class WebSettings(BaseSettings):
    enabled: bool = True
    enable_public_log: bool = False
    app_title: str = 'ACME CA Server'
    app_description: str = 'Self-hosted ACME CA Server'
    model_config = SettingsConfigDict(env_prefix='web_', secrets_dir='/run/secrets')


class CaSettings(BaseSettings):
    enabled: bool = True
    cert_lifetime: timedelta = timedelta(days=60)
    crl_lifetime: timedelta = timedelta(days=7)
    cert_cdp_enabled: bool = True
    encryption_key: SecretStr | None = None  # encryption of private keys in database
    import_dir: Path = Path('/import')

    model_config = SettingsConfigDict(env_prefix='ca_', secrets_dir='/run/secrets')

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
    host: str | None = None
    port: int | None = None
    username: str | None = None
    password: SecretStr | None = None
    encryption: Literal['tls', 'starttls', 'plain', 'tls-nonstrict', 'starttls-nonstrict'] = 'tls'
    sender: EmailStr | None = None
    notify_on_account_creation: bool = True
    warn_before_cert_expires: timedelta | Literal[False] = timedelta(days=20)
    notify_when_cert_expired: bool = True

    model_config = SettingsConfigDict(env_prefix='mail_', secrets_dir='/run/secrets')

    @model_validator(mode='before')
    @classmethod
    def sanitize_values(cls, values: Any) -> Any:
        if 'warn_before_cert_expires' in values and (values['warn_before_cert_expires'] or '').lower().strip() in ('', 'false', '0', '-1'):
            values['warn_before_cert_expires'] = False
        return values

    @model_validator(mode='after')
    def valid_check(self) -> 'MailSettings':
        if self.enabled and (not self.host or not self.sender):
            raise ValueError('Mail parameters (mail_host, mail_sender) are missing as SMTP is enabled')
        if (self.username and not self.password) or (not self.username and self.password):
            raise ValueError('Either no mail auth must be specified or username and password must be provided')
        if self.enabled and not self.port:
            self.port = {'tls': 465, 'starttls': 587, 'plain': 25, 'tls-nonstrict': 465, 'starttls-nonstrict': 587}[self.encryption]
        return self

    @property
    def tls_non_strict(self) -> bool:
        return self.encryption.endswith('-nonstrict')


class AcmeSettings(BaseSettings):
    terms_of_service_url: AnyHttpUrl | None = None
    mail_target_regex: Pattern = re.compile(r'[^@]+@[^@]+\.[^@]+')
    mail_required: bool = True
    target_domain_regex: Pattern = re.compile(r'[^\*]+\.[^\.]+')  # disallow wildcard

    # one line per account: <account jwk thumbprint>:<domain a>,<domain b>
    prevalidated_domains: Annotated[dict[str, frozenset[str]], NoDecode] = {}

    model_config = SettingsConfigDict(env_prefix='acme_', secrets_dir='/run/secrets')

    @property
    def mailto_target_regex_pattern(self) -> Pattern:
        pattern = f'^mailto:{self.mail_target_regex.pattern.strip().removeprefix("^").removesuffix("$")}$'
        return re.compile(pattern)

    @property
    def target_domain_regex_pattern(self) -> Pattern:
        pattern = f'^{self.target_domain_regex.pattern.strip().removeprefix("^").removesuffix("$")}$'
        return re.compile(pattern)

    @field_validator('mail_target_regex', 'target_domain_regex')
    @classmethod
    def pattern_must_be_lowercase(cls, value: Pattern) -> Pattern:
        if value.pattern != value.pattern.lower():
            raise ValueError(f'pattern must be lowercase only, got {value.pattern!r}')
        return value

    @field_validator('prevalidated_domains', mode='before')
    @classmethod
    def parse_prevalidated_domains(cls, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        result: dict[str, set[str]] = {}
        for entry in value.splitlines():
            if not entry.strip():
                continue
            account, sep, domains = entry.partition(':')
            account = account.strip()
            domain_set = {domain.strip().lower() for domain in domains.split(',') if domain.strip()}
            if not sep or not account or not domain_set:
                raise ValueError(f'Invalid entry "{entry.strip()}" in acme_prevalidated_domains, expected format: one line per account, <account>:<domain a>,<domain b>')
            result.setdefault(account, set()).update(domain_set)
        return result

    @model_validator(mode='after')
    def check_prevalidated_domains(self) -> 'AcmeSettings':
        for account, domains in self.prevalidated_domains.items():
            for domain in domains:
                if not self.target_domain_regex_pattern.fullmatch(domain):
                    raise ValueError(f'Domain "{domain}" of account "{account}" in acme_prevalidated_domains does not match acme_target_domain_regex')
        return self


class Settings(BaseSettings):
    external_url: AnyHttpUrl
    db_dsn: PostgresDsn
    log_level: Literal['debug', 'info', 'warning', 'error'] = 'info'
    acme: AcmeSettings = AcmeSettings()
    ca: CaSettings = CaSettings()
    mail: MailSettings = MailSettings()
    web: WebSettings = WebSettings()

    model_config = SettingsConfigDict(secrets_dir='/run/secrets')

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


settings = Settings()  # type: ignore[call-arg]

logger.setLevel(settings.log_level.upper())

logger.debug('Settings: %s', settings.model_dump())
