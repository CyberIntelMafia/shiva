from abc import ABC, abstractmethod
from typing import Any


class BaseIntegration(ABC):

    @abstractmethod
    def get_file_analysis(self, sha256: str) -> str:
        """Method to get result for API."""
        pass

    @abstractmethod
    def _is_api_key_valid(self):
        pass
