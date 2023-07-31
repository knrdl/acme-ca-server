from datetime import datetime
from email.mime.text import MIMEText
from typing import Literal

from aiosmtplib import SMTP
from jinja2 import Environment, FileSystemLoader

from config import settings
from logger import logger

template_engine = Environment(loader=FileSystemLoader('mail/templates'), enable_async=True, autoescape=True)
default_params = {
    'app_title': settings.web.app_title,
    'app_desc': settings.web.app_description,
    'web_url': str(settings.external_url),
    'acme_url': str(settings.external_url).removesuffix('/') + '/acme/directory'
}

Templates = Literal[
    'cert-expired-info', 'cert-expires-warning', 'new-account-info']


async def send_mail(receiver: str, template: Templates, subject_vars: dict = None, body_vars: dict = None):
    subject_vars = subject_vars or {}
    subject_vars.update(**default_params)
    body_vars = body_vars or {}
    body_vars.update(**default_params)
    subject_job = template_engine.get_template(template + '/subject.txt')\
        .render_async(subject_vars)
    body_job = template_engine.get_template(template + '/body.html')\
        .render_async(body_vars)
    message = MIMEText(await body_job, 'html', 'utf-8')
    message['From'] = settings.mail.sender
    message['To'] = receiver
    message['Subject'] = await subject_job
    if settings.mail.enabled:
        auth = {}
        if settings.mail.username and settings.mail.password:
            auth = {'username': settings.mail.username, 'password': settings.mail.password.get_secret_value()}
        async with SMTP(
            hostname=settings.mail.host, port=settings.mail.port, **auth,
            use_tls=settings.mail.encryption == 'tls', start_tls=settings.mail.encryption == 'starttls'
        ) as client:
            await client.send_message(message)
    else:
        logger.debug('sending mails is disabled, not sending: ' + str(message))


async def send_new_account_info_mail(receiver: str):
    await send_mail(receiver, 'new-account-info')


async def send_certs_will_expire_warn_mail(*, receiver: str, domains: list[str], expires_at: datetime, serial_number: str):
    await send_mail(receiver, 'cert-expires-warning', body_vars={
        'domains': domains,
        'expires_at': expires_at,
        'serial_number': serial_number,
        'expires_in_days': (expires_at.replace(tzinfo=None) - datetime.utcnow()).days
    })


async def send_certs_expired_info_mail(*, receiver: str, domains: list[str], expires_at: datetime, serial_number: str):
    await send_mail(receiver, 'cert-expired-info', body_vars={
        'domains': domains,
        'expires_at': expires_at,
        'serial_number': serial_number
    })
