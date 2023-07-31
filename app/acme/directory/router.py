from fastapi import APIRouter

from config import settings

api = APIRouter(tags=['acme:directory'])


@api.get('/directory')
async def get_directory():
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
        'meta': meta
    }
