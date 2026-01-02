from abc import ABC, abstractmethod
from core.models import ReputationResult


class OsintProvider(ABC):
    name: str

    @abstractmethod
    def check_url(self, url: str) -> ReputationResult:
        pass
