class SolomonException(Exception):  # noqa: N818 - public compatibility name
    """Base exception for Solomon."""

    pass


class ConfigurationError(SolomonException):
    pass


class CapabilityError(SolomonException):
    pass


class PrivilegeError(SolomonException):
    pass


class CollectionError(SolomonException):
    pass


class ValidationError(SolomonException):
    pass


class ScopeError(SolomonException):
    pass
