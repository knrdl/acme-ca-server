from fastapi import APIRouter, Response

from config import settings

from .service import generate

api = APIRouter(tags=['acme:nonce'])


@api.head('/new-nonce', status_code=200)
@api.get('/new-nonce', status_code=204)
async def get_nonce(response: Response):
    response.headers['Replay-Nonce'] = await generate()
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Link'] = f'<{settings.external_url}/acme/directory>;rel="index"'
