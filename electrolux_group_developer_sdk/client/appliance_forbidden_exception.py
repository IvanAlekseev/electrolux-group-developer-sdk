from typing import Optional

from .client_exception import ApplianceClientException


class ApplianceForbiddenException(ApplianceClientException):
    """Exception raised when an appliance resource is not owned by client or not registered (HTTP 403 FORBIDDEN_RESOURCE)."""

    def __init__(
        self,
        message: str = "Appliance resource is not owned by client or not registered.",
        status: Optional[int] = 403,
        error_code: Optional[str] = "FORBIDDEN_RESOURCE",
    ):
        super().__init__(message, status=status)
        self.error_code = error_code
