from config import settings
from fastapi import APIRouter

api = APIRouter(tags=['acme:directory'])


@api.get('/directory')
async def get_directory():
    """
    See RFC 8555 7.1.1 "Directory" <https://www.rfc-editor.org/rfc/rfc8555#section-7.1.1>
    """

    meta = {'website': settings.external_url}
    if settings.acme.terms_of_service_url:
        meta['termsOfService'] = settings.acme.terms_of_service_url
    return {
        'newNonce': f'{settings.external_url}acme/new-nonce',
        'newAccount': f'{settings.external_url}acme/new-account',
        'newOrder': f'{settings.external_url}acme/new-order',
        'revokeCert': f'{settings.external_url}acme/revoke-cert',
        'keyChange': f'{settings.external_url}acme/key-change',
        # newAuthz: is not supported
        'meta': meta,
    }
