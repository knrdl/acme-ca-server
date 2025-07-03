from config import settings
from fastapi import APIRouter, Response, status

from .service import generate

api = APIRouter(tags=['acme:nonce'])


@api.head('/new-nonce', status_code=status.HTTP_200_OK)
@api.get('/new-nonce', status_code=status.HTTP_204_NO_CONTENT)
async def get_nonce(response: Response):
    """
    See RFC 8555 7.2 "Getting a Nonce" <https://www.rfc-editor.org/rfc/rfc8555#section-7.2>
    """
    response.headers['Replay-Nonce'] = await generate()
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Link'] = f'<{settings.external_url}acme/directory>;rel="index"'
