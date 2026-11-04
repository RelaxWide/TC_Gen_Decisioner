from abc import ABC, abstractmethod
from datetime import datetime, timezone


class TCExecutor(ABC):
    @abstractmethod
    def execute(self, tc_record: dict) -> dict:
        ...


class SSHTCExecutor(TCExecutor):
    """Executes TC steps against the real target over SSH (plink + nvme-cli passthru)."""

    def __init__(self, allow_destructive: bool = False):
        self.allow_destructive = allow_destructive

    def execute(self, tc_record: dict) -> dict:
        from tc_system.execution.ssh_runner import execute_tc_steps

        result = execute_tc_steps(tc_record["steps"], allow_destructive=self.allow_destructive)
        return {
            "executor": "SSHTCExecutor",
            "executed_at": datetime.now(timezone.utc).isoformat(),
            "step_results": result["step_results"],
            "dmesg_text": result["dmesg_text"],
            "batch_stderr": result["batch_stderr"],
            "timed_out": result["timed_out"],
            "dmesg_captured_scoped": result["dmesg_captured_scoped"],
        }
