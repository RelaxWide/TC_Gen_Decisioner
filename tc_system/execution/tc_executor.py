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
        from tc_system.execution import ssh_runner
        from tc_system.execution.ssh_runner import DestructiveStepBlocked, passthru_cmd
        from tc_system.execution.expectation_checker import status_line
        from tc_system.verification import completion_status, evaluate_check, expected_status, integer, matches_expected

        steps = tc_record["steps"]
        tc_id, attempt_id = tc_record["tc_id"], tc_record.get("active_attempt_id")
        # Validate the WHOLE chain before an earlier destructive step can run.
        for i, step in enumerate(steps):
            if not step.get("host_action"):
                passthru_cmd(step)
            if not self.allow_destructive and (step.get("destructive") or step.get("firmware_state")):
                raise DestructiveStepBlocked(f"--no-destructive: 스텝 {i} {step.get('name') or '?'}"
                                             f"(opcode {step.get('opcode')})이 체인에 포함돼 보내지 않음")
        results, stderr = [], []
        state = {"timed_out": False}
        conditions = tc_record["verification_contract"].get("precondition_checks", [])
        snapshots = [i for i, s in enumerate(steps) if s.get("harness") == "snapshot"]
        cleanups = [i for i, s in enumerate(steps) if s.get("phase") == "cleanup"]

        def send(i, step):
            if step.get("host_action"):
                host = ssh_runner.run_host_action(step["host_action"], step["device"], tc_id=tc_id,
                                                  attempt_id=attempt_id, step_index=i,
                                                  firmware=step.get("firmware_image"))
                stderr.append(host["batch_stderr"])
                state["timed_out"] = state["timed_out"] or host["timed_out"]
                return {"step_index": i, "exit_code": host["exit_code"], "stdout": host["stdout"],
                        "started": True, "host_action": step["host_action"]}
            result = ssh_runner.execute_tc_steps([step], allow_destructive=self.allow_destructive, tc_id=tc_id,
                                                 attempt_id=attempt_id, step_index=i, clear_dmesg=False,
                                                 dump_dmesg=False)
            stderr.append(result["batch_stderr"])
            state["timed_out"] = state["timed_out"] or result["timed_out"]
            return dict(result["step_results"][0], step_index=i)

        # The log boundary comes before the first action of any kind: a reset
        # as the first step used to run before the clear, and its warnings
        # vanished (or, if nothing cleared, boot-time logs were reported as this
        # TC's). A failed clear means the dump is not scoped.
        try:
            scoped = bool(ssh_runner.clear_dmesg(tc_id=tc_id, attempt_id=attempt_id))
        except Exception:  # the dump is then simply not scoped to this TC
            scoped = False
        blocked = None
        try:
            for i, step in enumerate(steps):
                if step.get("phase") == "cleanup":
                    continue
                if not blocked and not step.get("harness"):
                    blocked = self._unrestorable(i, step, steps, snapshots, {r["step_index"]: r for r in results})
                if blocked:
                    results.append({"step_index": i, "started": False, "exit_code": None,
                                    "stdout": "", "blocked_reason": blocked})
                    continue
                # Recorded before sending: if the call never returns (Ctrl+C,
                # SSH error) the controller may already have applied it, and
                # the finally below must still restore (review F01).
                pending = {"step_index": i, "started": True, "exit_code": None, "stdout": "", "in_flight": True}
                results.append(pending)
                current = send(i, step)
                results[results.index(pending)] = current
                if step.get("harness"):
                    continue  # saving state: never stops the chain or evaluates its checks
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
        finally:
            # Always, also on an exception or Ctrl+C: put back what was changed.
            self._run_cleanups(cleanups, steps, snapshots, results, send, state)
        dmesg_text = ssh_runner.capture_dmesg(tc_id=tc_id, attempt_id=attempt_id)
        results.sort(key=lambda r: r["step_index"])
        return {"executor": "SSHTCExecutor", "executed_at": datetime.now(timezone.utc).isoformat(),
                "step_results": results, "dmesg_text": dmesg_text,
                "batch_stderr": "\n".join(stderr), "timed_out": state["timed_out"],
                "dmesg_captured_scoped": scoped}

    def _run_cleanups(self, cleanups, steps, snapshots, results, send, state):
        from tc_system.verification import completion_status
        for i in cleanups:
            by_index = {r["step_index"]: r for r in results}
            step = steps[i]
            guards = (step.get("restore") or {}).get("guards") or []
            if guards and not any(self._may_have_changed(by_index.get(g)) for g in guards):
                # Never sent, or the drive refused it: nothing was changed
                # (a correctly rejected negative test is not "unrestored").
                results.append({"step_index": i, "started": False, "exit_code": None, "stdout": "",
                                "cleanup_not_needed": "값을 바꾸는 스텝이 보내지지 않았거나 장비가 처리 전에 인자를 "
                                                      "거부해(Invalid Field 등) 바뀐 것이 없음"})
                continue
            step, skip = self._restore_values(step, steps, snapshots, by_index)
            if state["timed_out"]:
                skip = "장비가 응답하지 않아(타임아웃) 원복 스텝을 보내지 않음"
            if skip:
                results.append({"step_index": i, "started": False, "exit_code": None, "stdout": "",
                                "cleanup_skipped": skip})
                continue
            try:
                current = send(i, step)
            except Exception as exc:  # one failed restore must not stop the others
                results.append({"step_index": i, "started": False, "exit_code": None, "stdout": "",
                                "cleanup_skipped": f"원복 전송 실패: {type(exc).__name__}: {exc}"})
                continue
            current["sent"] = {"cdw10": step["cdw10"], "cdw11": step["cdw11"], "data_len": step["data_len"]}
            results.append(current)
            snap = (step.get("restore") or {}).get("from_snapshot")
            if snap is not None and completion_status(current) == "SUCCESS":
                # Read it back: a restore that "succeeded" into the wrong
                # register (review: PLM/RRL) is caught here, not assumed.
                try:
                    check = send(snapshots[snap], steps[snapshots[snap]])
                except Exception as exc:
                    current.update(restore_verified=None, restore_check=f"원복 확인 실패: 다시 읽기 전송 실패 — {exc}")
                    continue
                current["restore_verified"], current["restore_check"] = self._same_value(
                    steps[snapshots[snap]], by_index.get(snapshots[snap]), check)

    @staticmethod
    def _may_have_changed(result):
        """A change step took effect, or may have: completed successfully, or
        its outcome is unknown (in flight, timed out, no status), or it failed
        while processing (Internal Error ...). Only a rejection of its own
        parameters (spec_fields.REJECTED_BEFORE_EFFECT) changed nothing."""
        from tc_system import spec_fields
        from tc_system.verification import completion_status
        if not result or not result.get("started", True):
            return False
        if result.get("in_flight") or result.get("exit_code") is None:
            return True
        status = completion_status(result)
        if status is None or status == "SUCCESS":
            return True
        code = spec_fields.status_code_in_output(result.get("stdout", "")) or spec_fields.status_code_of_name(status)
        return code not in spec_fields.REJECTED_BEFORE_EFFECT

    @staticmethod
    def _snapshot_problem(snap_index, snap_step, snap_result):
        """Why a snapshot does not hold a complete original value, else None.
        A SUCCESS line alone is not enough (review: no DW0 captured -> the
        restore wrote 0; 1 of 256 APST bytes captured -> no restore)."""
        import re
        from tc_system import spec_fields
        from tc_system.verification import completion_status, decode_payload
        if completion_status(snap_result) != "SUCCESS":
            return f"원래 값을 읽는 스텝 {snap_index}가 성공하지 않음"
        codec = spec_fields.FEATURE_CODECS.get(snap_step.get("codec_fid")) or {}
        if codec.get("value") and not re.search(r"\bresult:\s*0x[0-9a-fA-F]+", str(snap_result.get("stdout", ""))):
            return f"원래 값을 읽는 스텝 {snap_index}의 CQE Dword 0이 캡처되지 않음"
        if snap_step.get("data_len"):
            data = decode_payload(snap_result)
            if data is None or len(data) != snap_step["data_len"]:
                got = 0 if data is None else len(data)
                return f"원래 값을 읽는 스텝 {snap_index}의 버퍼가 {got}/{snap_step['data_len']}바이트만 캡처됨"
        return None

    @classmethod
    def _unrestorable(cls, i, step, steps, snapshots, by_index):
        """Why step i must not be sent: it would change a value we could not
        save whole, cannot write back, or cannot undo at all. A negative test
        (expected rejection) of a restorable value is still sent; if the drive
        accepts it anyway a skipped restore is a "꼭 확인" review reason."""
        from tc_system import spec_fields
        from tc_system.generation.tc_writer import restore_identity
        from tc_system.verification import expected_status, integer
        if step.get("mode") == "admin-passthru" and integer(step.get("opcode", "0x0")) == 0x09:
            irreversible = spec_fields.irreversible_feature_value(integer(step.get("cdw10", "0x0")) & 0xFF,
                                                                  integer(step.get("cdw11", "0x0")))
            if irreversible:
                return irreversible  # whatever the expected status: it could stick
        if expected_status(step) != "SUCCESS":
            return None
        for cleanup in steps:
            restore = cleanup.get("restore") or {}
            if i not in restore.get("guards", []):
                continue
            if not cleanup.get("restorable", True):
                return cleanup.get("unrestorable_reason") or f"스텝 {i}가 바꿀 값을 되돌릴 수 없어 보내지 않음"
            if restore.get("identity") and restore_identity(step) != restore["identity"]:
                return (f"스텝 {i} {step.get('name')}의 원복 대상(FID/SV/NSID/인스턴스)이 백업한 대상과 다름 — "
                        "재시도 등으로 바뀐 값은 되돌릴 수 없어 보내지 않음")
            if restore.get("from_snapshot") is not None:
                snap = snapshots[restore["from_snapshot"]]
                problem = cls._snapshot_problem(snap, steps[snap], by_index.get(snap))
                if problem:
                    return f"{problem}(원복 불가) — 상태를 바꾸는 스텝 {i} {step.get('name')}부터 보내지 않음"
        return None

    @classmethod
    def _restore_values(cls, step, steps, snapshots, by_index):
        """A restore step's fields from the value its snapshot read, encoded
        per FID (spec_fields.FEATURE_CODECS). Returns (step, reason not to send)."""
        import re
        from tc_system import spec_fields
        from tc_system.verification import decode_payload, integer
        restore = step.get("restore")
        if not restore:
            return step, None
        if not step.get("restorable", True):
            return step, step.get("unrestorable_reason") or "원래 값을 되돌릴 방법이 없음"
        if restore.get("from_snapshot") is None:
            return step, None
        snap_index = snapshots[restore["from_snapshot"]]
        snap = by_index.get(snap_index)
        problem = cls._snapshot_problem(snap_index, steps[snap_index], snap)
        if problem:
            return step, problem
        codec = spec_fields.FEATURE_CODECS[step["codec_fid"]]
        step = dict(step)
        if codec["value"]:
            dw0 = int(re.search(r"\bresult:\s*(0x[0-9a-fA-F]+)", str(snap.get("stdout", "")))[1], 16)
            step["cdw11"] = f"0x{(integer(step['cdw11']) & codec['instance']) | (dw0 & codec['value']):08X}"
        if step["data_len"]:
            data = bytearray(decode_payload(snap)[:step["data_len"]])
            for lo, hi in codec["set_reserved"]:
                data[lo:hi] = bytes(hi - lo)  # reserved in Set (Timestamp attributes)
            step["payload_hex"] = bytes(data).hex()
        return step, None

    @staticmethod
    def _same_value(snap_step, before, after):
        """(True/False/None, detail): the read-back equals the original."""
        import re
        from tc_system import spec_fields
        from tc_system.verification import completion_status, decode_payload
        if completion_status(after) != "SUCCESS":
            return None, (f"원복 확인 실패: 다시 읽기가 성공하지 않음 — "
                          f"{completion_status(after) or str((after or {}).get('stdout', ''))[:160]}")
        codec = spec_fields.FEATURE_CODECS.get(snap_step.get("codec_fid")) or {}
        if codec.get("approx"):
            return None, "근사 원복: 시간 값이라 정확히 같을 수 없음"
        if codec.get("value"):
            pick = lambda r: int(re.search(r"\bresult:\s*(0x[0-9a-fA-F]+)", str(r.get("stdout", "")))[1], 16) & codec["value"]
            try:
                old, new = pick(before), pick(after)
            except TypeError:
                return None, "다시 읽은 CQE Dword 0이 없음"
            if old != new:
                return False, f"원래 값 0x{old:X}, 원복 후 0x{new:X}"
        if snap_step.get("data_len"):
            old, new = decode_payload(before), decode_payload(after)
            if old is None or new is None or old != new:
                return False, "원복 후 다시 읽은 버퍼가 원래 버퍼와 다름"
        return True, "원래 값과 같음"
