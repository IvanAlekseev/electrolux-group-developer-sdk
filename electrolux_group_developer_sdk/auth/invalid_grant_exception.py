from .token_refresh_failed import TokenRefreshFailedException


class InvalidGrantException(TokenRefreshFailedException):
    """Exception raised when a refresh token is rejected as invalid, expired, or revoked (OAuth invalid_grant)."""

    def __init__(self, message: str = "Refresh token was rejected as invalid or expired (invalid_grant)."):
        super().__init__(message)
