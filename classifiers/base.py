from abc import ABC, abstractmethod
from models import LogEntry, DetectionResult, ProfileContext


class BaseDetector(ABC):
    @abstractmethod
    def evaluate(self, entry: LogEntry, context: ProfileContext) -> list[DetectionResult]:
        """Return list of DetectionResults (empty if no fraud detected)."""
        ...
