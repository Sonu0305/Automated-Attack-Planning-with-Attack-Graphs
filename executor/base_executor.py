"""Abstract base class for all attack executors.

Every execution backend (Metasploit, SSH, CALDERA, PlaybookRunner)
implements this interface so that ``PlaybookRunner`` can dispatch steps
without knowing their concrete type.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from graph.models import AttackEdge, ExecutionResult


class BaseExecutor(ABC):
    """Abstract executor interface.

    All concrete executor classes must implement ``execute_step()``.
    They may also optionally implement ``setup()`` and ``teardown()``
    for session management.
    """

    def setup(self) -> None:
        """Perform any one-time initialisation before executing steps.

        Override in subclasses that need to establish connections or
        start background processes.
        """

    def teardown(self) -> None:
        """Clean up resources after all steps have been executed.

        Override in subclasses that hold persistent connections.
        """

    @abstractmethod
    def execute_step(self, edge: AttackEdge) -> ExecutionResult:
        """Execute one attack step represented by an ``AttackEdge``.

        Args:
            edge: The attack step to execute.

        Returns:
            ``ExecutionResult`` describing whether the step succeeded,
            the resulting session ID (if any), raw output, elapsed time,
            and IDS alert count.
        """
