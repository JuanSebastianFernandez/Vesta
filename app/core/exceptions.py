from fastapi import HTTPException, status
from typing import Any


class CustomException(HTTPException):
    """
    Base Class for custom HTTP exceptions.
    """
    def __init__(self, status_code: int, detail: Any):
        super().__init__(status_code=status_code, detail=detail)

class ModelLoadingError(CustomException):
    """
    Exceptions of this type are raised when the application fails to load necessary AI models.
    """
    def __init__(self, detail: Any = "Error charging AI models."):
        super().__init__(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=detail)

class RepositoryError(CustomException):
    """
    Exceptions of this type are raised when there is an issue with repository operations such as cloning.
    """
    def __init__(self, detail: Any = "Error in repository operations."):
        super().__init__(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=detail)

class AnalysisError(CustomException):
    """
    Exceptions of this type are raised when there is an error during code analysis.
    """
    def __init__(self, detail: Any = "Error during code analysis."):
        super().__init__(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=detail)
