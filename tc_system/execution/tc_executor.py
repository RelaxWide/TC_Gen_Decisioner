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
        if tc_record.get("verification_contract", {}).get("version") == 2:
            return self._execute_contract(tc_record)

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

    def _execute_contract(self, tc_record):
        from tc_system.execution.ssh_runner import (capture_dmesg, execute_tc_steps, passthru_cmd,
                                                    DestructiveStepBlocked)
        from tc_system.execution.expectation_checker import status_line
        from tc_system.verification import (completion_status, evaluate_check, expected_status,
                                            integer, matches_expected)

        steps = tc_record["steps"]
        # Validate the WHOLE chain before an earlier destructive step can run.
        for i, step in enumerate(steps):
            passthru_cmd(step)
            if not self.allow_destructive and (step.get("destructive") or step.get("firmware_state")):
                raise DestructiveStepBlocked(f"--no-destructive: 스텝 {i} {step.get('name') or '?'}"
                                             f"(opcode {step.get('opcode')})이 체인에 포함돼 보내지 않음")
        results, stderr = [], []
        scoped, timed_out, blocked = True, False, None
        conditions = tc_record["verification_contract"].get("precondition_checks", [])
        for i, step in enumerate(steps):
            if blocked:
                results.append({"step_index": i, "started": False, "exit_code": None,
                                "stdout": "", "blocked_reason": blocked})
                continue
            # One step per SSH call (the next step depends on this result), but
            # dmesg is cleared once before the first step and dumped once after
            # the last: n+2 plink connections per TC instead of 3n.
            result = execute_tc_steps([step], allow_destructive=self.allow_destructive,
                                      tc_id=tc_record["tc_id"],
                                      attempt_id=tc_record.get("active_attempt_id"),
                                      step_index=i, clear_dmesg=(i == 0), dump_dmesg=False)
            current = dict(result["step_results"][0], step_index=i)
            results.append(current)
            stderr.append(result["batch_stderr"])
            if i == 0:
                scoped = bool(result["dmesg_captured_scoped"])
            timed_out = timed_out or result["timed_out"]
            # The reason is stored on every step left unsent and shown as the
            # cause; "precondition check failed or could not be evaluated"
            # alone left the reader unable to tell which condition or value.
            if not matches_expected(step, current):
                actual = completion_status(current) or status_line(str(current.get("stdout", "")))
                blocked = (f"스텝 {i} {step.get('name') or ''}이(가) 기대 완료 상태 {expected_status(step)}가 "
                           f"아니라 {actual}(으)로 끝나 이후 스텝을 보내지 않음")
            by_index = {r["step_index"]: r for r in results}
            for condition in conditions:
                for check in condition["checks"]:
                    if blocked or integer(check["step"]) > i:
                        continue
                    outcome = evaluate_check(check, steps, by_index)
                    if outcome["result"] != "satisfied":
                        verdict = "불충족" if outcome["result"] == "violated" else "확인 불가"
                        blocked = (f"사전조건 '{condition['description']}' {verdict}(스텝 {check['step']} 관측: "
                                   f"{outcome['detail']}) — 이후 스텝을 보내지 않음")
        dmesg_text = capture_dmesg(tc_id=tc_record["tc_id"], attempt_id=tc_record.get("active_attempt_id"))
        return {"executor": "SSHTCExecutor", "executed_at": datetime.now(timezone.utc).isoformat(),
                "step_results": results, "dmesg_text": dmesg_text,
                "batch_stderr": "\n".join(stderr), "timed_out": timed_out,
                "dmesg_captured_scoped": scoped}
