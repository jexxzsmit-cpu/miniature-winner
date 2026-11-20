from dataclasses import dataclass, field
from time import monotonic
from typing import Callable


@dataclass(frozen=True)
class PortFanoutAlert:
    source_ip: str
    destination_ip: str
    unique_ports: int


@dataclass
class _ObservationWindow:
    started_at: float
    ports: set[int] = field(default_factory=set)
    alerted: bool = False


class PortFanoutDetector:
    def __init__(
        self,
        threshold: int = 20,
        window_seconds: float = 60.0,
        clock: Callable[[], float] = monotonic,
    ) -> None:
        if threshold < 1:
            raise ValueError("threshold must be at least 1")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be greater than 0")

        self.threshold = threshold
        self.window_seconds = window_seconds
        self._clock = clock
        self._windows: dict[tuple[str, str], _ObservationWindow] = {}
        self._next_cleanup_at = 0.0

    def observe(
        self, source_ip: str, destination_ip: str, destination_port: int
    ) -> PortFanoutAlert | None:
        if not 1 <= destination_port <= 65535:
            raise ValueError("destination_port must be between 1 and 65535")

        now = self._clock()
        self._cleanup_expired(now)

        key = (source_ip, destination_ip)
        observation = self._windows.get(key)
        if observation is None or now - observation.started_at >= self.window_seconds:
            observation = _ObservationWindow(started_at=now)
            self._windows[key] = observation

        observation.ports.add(destination_port)
        if len(observation.ports) < self.threshold or observation.alerted:
            return None

        observation.alerted = True
        return PortFanoutAlert(
            source_ip=source_ip,
            destination_ip=destination_ip,
            unique_ports=len(observation.ports),
        )

    def _cleanup_expired(self, now: float) -> None:
        if now < self._next_cleanup_at:
            return

        expired = [
            key
            for key, observation in self._windows.items()
            if now - observation.started_at >= self.window_seconds
        ]
        for key in expired:
            del self._windows[key]

        self._next_cleanup_at = now + min(self.window_seconds, 60.0)
