"""Engine-independent execution failure categories."""


class ChiExceededError(AssertionError):
    """Raised when accumulated execution cost exceeds the chi budget."""


class CallLimitExceededError(AssertionError):
    """Raised when execution exceeds the deterministic instruction budget."""


def classify_execution_error(error: BaseException | None) -> str:
    """Return the stable transaction-output category for an execution error."""
    if error is None:
        return "success"
    if isinstance(error, ChiExceededError):
        return "chi_exceeded"
    if isinstance(error, CallLimitExceededError):
        return "call_limit_exceeded"
    if isinstance(error, AssertionError):
        return "contract_assertion"
    return "contract_error"
