from urllib.parse import parse_qs
from channels.db import database_sync_to_async
from django.contrib.auth.models import AnonymousUser
from allauth.headless.tokens.strategies.jwt.internal import validate_access_token


@database_sync_to_async
def get_user(token_key):
    """
    Asynchronously get user from the database from a JWT.
    """
    user_payload = validate_access_token(token_key)
    if user_payload is None:
        return AnonymousUser()
    user, _payload = user_payload
    return user


class TokenAuthMiddleware:
    def __init__(self, inner):
        self.inner = inner

    async def __call__(self, scope, receive, send):
        query_string = scope.get("query_string", b"").decode("utf-8")
        query_params = parse_qs(query_string)
        token = query_params.get("token", [None])[0]

        scope['user'] = AnonymousUser() if token is None else await get_user(token)

        return await self.inner(scope, receive, send)
