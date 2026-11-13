"""Domain exceptions raised by the service layer."""


class BankError(Exception):
    """Base class for all expected (non-bug) domain errors."""


class ValidationError(BankError):
    """The request contained invalid or disallowed input."""


class NotFoundError(BankError):
    """The resource does not exist, or the caller may not know it exists."""


class AccountLockedError(BankError):
    """Too many failed logins; the account is temporarily locked."""
