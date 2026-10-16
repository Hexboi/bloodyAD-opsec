"""Results for mutative operations; successful requests are not transactions."""
from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class WriteOutcome:
    status: Literal["applied", "simulated", "unchanged", "partial"]
    operation: str
    target: str
    completed_steps: tuple[str, ...] = ()


class PartialWriteError(RuntimeError):
    def __init__(self, outcome):
        self.outcome = outcome
        super().__init__(f"Partially applied {outcome.operation}; completed steps: {', '.join(outcome.completed_steps)}")
