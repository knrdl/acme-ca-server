from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint


class SecurityHeadersMiddleware(BaseHTTPMiddleware):  # pylint: disable=too-few-public-methods
    """Add security headers to all responses."""

    def __init__(
        self,
        app: FastAPI,
        *,
        content_security_policy: dict[str, str] | None = None,
        permissions_policy: dict[str, str] | None = None,
    ) -> None:
        super().__init__(app)
        self.csp = content_security_policy
        self.pp = permissions_policy

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        """Dispatch of the middleware.

        :param request: Incoming request
        :param call_next: Function to process the request
        :return: Return response coming from processed request
        """
        headers = {
            'Cross-Origin-Opener-Policy': 'same-origin',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000',
        }
        if self.csp:
            matches = [
                path for path in self.csp.keys() if request.url.path.startswith(path)
            ]
            if matches:
                best_match = sorted(matches, key=len, reverse=True)[0]
                headers['Content-Security-Policy'] = self.csp[best_match]
        if self.pp:
            matches = [
                path for path in self.pp.keys() if request.url.path.startswith(path)
            ]
            if matches:
                best_match = sorted(matches, key=len, reverse=True)[0]
                headers['Permissions-Policy'] = self.pp[best_match]
        response = await call_next(request)
        response.headers.update(headers)

        return response
