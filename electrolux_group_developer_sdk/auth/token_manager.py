import asyncio
import logging
import time
from typing import Callable, Optional

import jwt

from .invalid_credentials_exception import InvalidCredentialsException
from .invalid_token_exception import InvalidTokenException
from .token_refresh_failed import TokenRefreshFailedException
from .auth_data import AuthData
from ..client.client_util import request
from ..config import TOKEN_REVOKE_URL, TOKEN_REFRESH_URL, USER_EMAIL_URL
from ..constants import GET, REFRESH_TOKEN, POST

_LOGGER = logging.getLogger(__name__)


def get_user_id_from_token(token: str) -> str:
    """Extract user id from token"""
    try:
        payload = jwt.decode(
            token,
            options={"verify_signature": False, "verify_exp": False},
        )
        user_id = payload.get("sub")
        if user_id is None:
            raise InvalidTokenException()
        return user_id
    except jwt.PyJWTError as e:
        raise InvalidTokenException(f"Failed to decode token: {e}") from e


class TokenManager:
    def __init__(
        self,
        access_token: str,
        refresh_token: str,
        api_key: str,
        on_token_update: Optional[Callable[[str, str, str], None]] = None,
        refresh_buffer_seconds: float = 60.0,
    ):
        """Initialize the token manager."""
        if access_token is None:
            _LOGGER.error("Access Token is missing")
            raise InvalidCredentialsException()
        self._on_token_update = on_token_update
        self.refresh_buffer_seconds = refresh_buffer_seconds
        self._refresh_lock = asyncio.Lock()
        self._auth_data = AuthData(access_token, refresh_token, api_key)

    def update(self, access_token: str, refresh_token: str, api_key: str) -> None:
        """Update the authentication data."""
        if self._on_token_update:
            self._on_token_update(access_token, refresh_token, api_key)
        self._auth_data = AuthData(access_token, refresh_token, api_key)

    def ensure_credentials(self) -> None:
        """Check if the token manager has the authentication data."""
        if self._auth_data.api_key is None:
            _LOGGER.error("API Key is missing")
            raise InvalidCredentialsException()
        if self._auth_data.access_token is None:
            _LOGGER.error("Access Token is missing")
            raise InvalidCredentialsException()
        if self._auth_data.refresh_token is None:
            _LOGGER.error("Refresh Token is missing")
            raise InvalidCredentialsException()

    def get_user_id(self) -> str:
        """Extract user id from stored token"""
        return get_user_id_from_token(self._auth_data.access_token)

    def is_token_valid(self, buffer_seconds: Optional[float] = None) -> bool:
        """Check token validity with configurable buffer."""
        if not self._auth_data or not self._auth_data.access_token:
            return False

        try:
            payload = jwt.decode(
                self._auth_data.access_token,
                options={"verify_signature": False, "verify_exp": False},
            )
            exp = payload.get("exp")
            if exp is None or not isinstance(exp, (int, float)):
                return False

            current_time = time.time()
            buffer = (
                buffer_seconds
                if buffer_seconds is not None
                else self.refresh_buffer_seconds
            )
            return (exp - current_time) > buffer

        except (jwt.PyJWTError, TypeError) as e:
            _LOGGER.error("Access Token is invalid - %s", e)
            return False

    async def refresh_token(self, force: bool = False) -> bool:
        auth_data = self._auth_data

        if not auth_data or auth_data.refresh_token is None:
            _LOGGER.error("Refresh token is missing")
            raise InvalidCredentialsException("Missing refresh token")

        initial_token = auth_data.access_token

        async with self._refresh_lock:
            # If another task refreshed the token while waiting on the lock, reuse it
            if (
                self._auth_data
                and self._auth_data.access_token != initial_token
                and self.is_token_valid()
            ):
                return True

            if not force and self.is_token_valid():
                return True

            payload = {REFRESH_TOKEN: self._auth_data.refresh_token}

            try:
                data = await request(method=POST, url=TOKEN_REFRESH_URL, json_body=payload)

                self.update(
                    access_token=data["accessToken"],
                    refresh_token=data["refreshToken"],
                    api_key=auth_data.api_key,
                )

                return True
            except Exception as e:
                _LOGGER.error("Error during token refresh: %s", e)
                return False

    async def revoke_token(self) -> bool:
        async with self._refresh_lock:
            auth_data = self._auth_data
            if not auth_data or auth_data.refresh_token is None:
                raise InvalidCredentialsException("Missing refresh token")

            payload = {REFRESH_TOKEN: auth_data.refresh_token}

            try:
                await request(method=POST, url=TOKEN_REVOKE_URL, json_body=payload)

                self._auth_data = None

                return True
            except Exception as e:
                _LOGGER.error("Error during token revoke: %s", e)
                return False

    async def get_auth_data(self, force_refresh: bool = False) -> AuthData:
        auth_data = self._auth_data
        if not auth_data or auth_data.access_token is None or auth_data.api_key is None:
            raise InvalidCredentialsException("Missing access token or API key")

        # Check if token is expired or force refresh requested
        if force_refresh or not self.is_token_valid():
            refreshed = await self.refresh_token(force=force_refresh)
            if not refreshed:
                raise TokenRefreshFailedException("Token expired and refresh failed")
            auth_data = self._auth_data

        return auth_data
