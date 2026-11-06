"""Offline review counterexamples; no device, SSH, credentials, or LLM calls.

Run from any directory with Python 3.10+. This writes only to stdout.
The expected column describes the desired invariant, not current behavior.
"""
from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import unittest  # also activates the project's built-in real-SSH guard
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from log_judge import judge
from log_judge.models import make_failure_context
from shared import llm_client
from shared.file_store import load_json, save_json_atomic
import config
import run_judge
from tc_system import pipeline
from tc_system.execution import ssh_runner
from tc_system.execution.expectation_checker import check_expectation, describe_outcome
from tc_system.execution.tc_executor import SSHTCExecutor
from tc_system.generation import scenario_generator, tc_writer
from tc_system.review import downgrade_verdict, review_tc
from tc_system.verification import validate_plan_contract, verify_tc


def step(**overrides):
    s = dict(name="Set Features", phase="action", mode="admin-passthru", device="/dev/nvme0",
             opcode="0x09", nsid=1, cdw10="0x04", cdw11="0x12c", cdw12="0x0", cdw13="0x0",
             cdw14="0x0", cdw15="0x0", data_len=0, direction="none", expected_status="SUCCESS",
             args_source="authored", field_constraints=[], test_intent={}, destructive=False,
             firmware_state=False, lockout_risk=False, shared_facts={})
    s.update(overrides)
    return s


def reply(value=0, data=None, error=None):
    r = dict(step_index=0, started=True, exit_code=22 if error else 0,
             stdout=(f"NVMe status: {error}: synthetic rejection" if error else
                     "Admin Command Synthetic is Success" +
                     (f" and result: 0x{value:08x}" if value is not None else "")))
    if data is not None:
        r["data_hex"] = data.hex()
    return r


QUOTE = "This synthetic requirement shall observe the completion of the command."


def tc_for(steps, **contract_fields):
    i = next(i for i, s in enumerate(steps) if s["phase"] == "action")
    contract = dict(version=2, precondition_checks=[], evidence=[dict(evidence_id="e", text=QUOTE)],
                    requirements=[dict(requirement_id="r", section_id="synthetic", evidence_id="e",
                                       quote=QUOTE, description="synthetic completion", checks=[dict(kind="completion", step=i)])])
    contract.update(contract_fields)
    return dict(tc_id="offline-review", name="offline-review", steps=steps, uses_placeholder_args=False,
                scenario=dict(preconditions=[]), verification_contract=contract)


def run(tc, handler, host=None):
    sent = []

    def wire(batch, **kwargs):
        s = deepcopy(batch[0])
        sent.append(s)
        return dict(step_results=[handler(s)], batch_stderr="", timed_out=False, dmesg_captured_scoped=True)

    with patch.object(ssh_runner, "execute_tc_steps", side_effect=wire), \
         patch.object(ssh_runner, "capture_dmesg", return_value="synthetic prior-boot message"), \
         patch.object(ssh_runner, "run_host_action", side_effect=host or AssertionError("unexpected host call")):
        execution = SSHTCExecutor(allow_destructive=True).execute(tc)
    return execution, sent


def with_restore(action):
    a, b = tc_writer.plan_state_restore([action], "/dev/nvme0", "/dev/nvme0n1")
    return tc_for(a + [action] + b)


def irreversible_write_protection():
    action = step(cdw10="0x84", cdw11="0x3")
    tc = with_restore(action)
    pipeline._preflight(tc, allow_destructive=False)
    state = {"wps": 0}

    def device(s):
        if int(s["opcode"], 16) == 0x0A:
            return reply(state["wps"])
        if state["wps"] in (2, 3):
            return reply(error="FEATURE_NOT_CHANGEABLE")
        state["wps"] = int(s["cdw11"], 16) & 7
        return reply()

    execution, sent = run(tc, device)
    return dict(expected={"admitted_without_destructive_permission": False, "final_wps": 0},
                actual=dict(admitted_without_destructive_permission=True, final_wps=state["wps"],
                            tc_status=check_expectation(tc, execution),
                            cleanup_status=execution["step_results"][-1]["stdout"],
                            sent=[s["name"] for s in sent]))


def feature_register_restore(fid, initial, changed, length):
    tc = with_restore(step(cdw10=hex(fid), cdw11="0x1", cdw12=hex(changed), data_len=length,
                           direction="write" if length else "none"))
    state = {"value": initial}

    def device(s):
        if int(s["opcode"], 16) == 0x0A:
            return reply(state["value"], bytes(length) if length else None)
        value = int(s["cdw12"], 16)
        if fid == 0x14 and value not in (1, 2):
            return reply(error="INVALID_FIELD")
        state["value"] = value
        return reply()

    execution, sent = run(tc, device)
    return dict(expected={"final_value": initial}, actual=dict(final_value=state["value"],
                cleanup_cdw11=sent[-1]["cdw11"], cleanup_cdw12=sent[-1]["cdw12"],
                cleanup_status=execution["step_results"][-1]["stdout"]))


def timestamp_restore_payload():
    tc = with_restore(step(cdw10="0x0e", data_len=8, direction="write"))
    payload = bytes.fromhex("0100000000000200")  # Origin=001b in Get Features byte 6

    def device(s):
        return reply(0, payload) if int(s["opcode"], 16) == 0x0A else reply()

    _, sent = run(tc, device)
    restored = bytes.fromhex(sent[-1]["payload_hex"])
    return dict(expected={"set_features_reserved_bytes": "0000"},
                actual={"set_features_reserved_bytes": restored[6:8].hex()})


def incomplete_snapshot(payload=False):
    tc = with_restore(step(cdw10="0x0c" if payload else "0x04", cdw11="0x0" if payload else "0x12c",
                           data_len=256 if payload else 0, direction="write" if payload else "none"))
    changed = []

    def device(s):
        if int(s["opcode"], 16) == 0x0A:
            return reply(1 if payload else None, b"\xab" if payload else None)
        changed.append(dict(phase=s["phase"], cdw11=s["cdw11"]))
        return reply()

    execution, sent = run(tc, device)
    return dict(expected={"action_sent": False}, actual=dict(action_sent=any(s["phase"] == "action" for s in sent),
                writes=changed, cleanup_skipped=execution["step_results"][-1].get("cleanup_skipped")))


def retry_identity(save=False):
    original = step(cdw10="0x05", cdw11="0x12c")
    original["test_intent"] = dict(field_constraints=[dict(field="cdw10", mask="0xff", value="0x05")],
                                   expected_status="SUCCESS")
    original["field_constraints"] = original["test_intent"]["field_constraints"]
    tc = with_restore(original)
    section = dict(section_id="synthetic", spec_doc="synthetic")
    op = dict(name="Set Features", command_set="ADMIN", raw_opcode="0x09", opcode="0x09a")
    resolved = [dict(section=section, opcode_entry=dict(op, name=s["name"]), phase=s["phase"],
                     harness=bool(s.get("harness"))) for s in tc["steps"]]
    authored = dict(cdw10="0x80000005" if save else "0x05", cdw11="0x12c", cdw12="0x0",
                    nsid=1 if save else 0xFFFFFFFF, data_len=0, direction="none", shared_facts={},
                    field_breakdown="synthetic retry")
    with patch.object(tc_writer, "author_args", return_value=authored):
        tc["steps"] = tc_writer.reauthor_steps(tc, resolved, dict(step_index=1, reason="synthetic rejection"), 1)
    state = {1: 100, 2: 200, "saved1": 150}

    def device(s):
        if int(s["opcode"], 16) == 0x0A:
            return reply(state[s["nsid"]])
        value = int(s["cdw11"], 16)
        for nsid in ([1, 2] if s["nsid"] == 0xFFFFFFFF else [s["nsid"]]):
            state[nsid] = value
        if int(s["cdw10"], 16) >> 31:
            state["saved1"] = value
        return reply()

    execution, sent = run(tc, device)
    expected = {"saved1": 150} if save else {"namespace2": 200}
    actual = {"saved1": state["saved1"]} if save else {"namespace2": state[2]}
    actual.update(action_nsid=sent[1]["nsid"], cleanup_nsid=sent[-1]["nsid"],
                  action_cdw10=sent[1]["cdw10"], cleanup_cdw10=sent[-1]["cdw10"])
    return dict(expected=expected, actual=actual)


def host_first_scoping():
    host = step(name="Controller Reset", phase="setup", mode="host", opcode="host:controller_reset",
                host_action="controller_reset", device="/dev/nvme0")
    action = step(name="Get Features", opcode="0x0A")
    tc = tc_for([host, action])
    hreply = dict(exit_code=98, stdout="NOT_READY_AFTER_SEC=30", batch_stderr="", timed_out=False)
    execution, sent = run(tc, lambda s: (_ for _ in ()).throw(AssertionError("action should not run")),
                          host=lambda *a, **k: hreply)
    return dict(expected={"dmesg_captured_scoped": False}, actual=dict(
        dmesg_captured_scoped=execution["dmesg_captured_scoped"], nvme_calls=len(sent),
        captured=execution["dmesg_text"]))


def host_first_success_log_loss():
    host = step(name="Controller Reset", phase="setup", mode="host", opcode="host:controller_reset",
                host_action="controller_reset", device="/dev/nvme0")
    tc = tc_for([host, step(name="Get Features", opcode="0x0A")])
    kernel_log = []
    stages = []

    def reset(*args, **kwargs):
        stages.append("reset")
        kernel_log.append("synthetic reset warning")
        return dict(exit_code=0, stdout="READY", batch_stderr="", timed_out=False)

    def wire(batch, **kwargs):
        if kwargs["clear_dmesg"]:
            stages.append("clear dmesg")
            kernel_log.clear()
        stages.append("action")
        return dict(step_results=[reply()], batch_stderr="", timed_out=False, dmesg_captured_scoped=True)

    with patch.object(ssh_runner, "run_host_action", side_effect=reset), \
         patch.object(ssh_runner, "execute_tc_steps", side_effect=wire), \
         patch.object(ssh_runner, "capture_dmesg", side_effect=lambda **k: "\n".join(kernel_log)):
        execution = SSHTCExecutor(True).execute(tc)
    return dict(expected={"reset_warning_preserved": True}, actual=dict(
        reset_warning_preserved="synthetic reset warning" in execution["dmesg_text"], stages=stages))


def judge_normalization():
    return dict(expected={"negated_classification": "needs_engineer_review", "nan_confidence": 0.0},
                actual=dict(negated_classification=judge._as_classification("not a firmware defect"),
                            nan_confidence=judge._as_confidence("NaN")))


def unmeasured_failure():
    q = "For a Discovery controller, the controller shall abort this command with Invalid Field in Command."
    tc = tc_for([step(name="Get Features", opcode="0x0A", expected_status="INVALID_FIELD")],
                unmeasured_preconditions=["the controller is a Discovery controller"])
    tc["verification_contract"]["evidence"][0]["text"] = q
    tc["verification_contract"]["requirements"][0]["quote"] = q
    execution = dict(step_results=[reply()], timed_out=False, dmesg_text="")
    tc.update(execution=execution, status=check_expectation(tc, execution), verification=verify_tc(tc, execution))
    verdict = downgrade_verdict(dict(classification="firmware_defect", confidence=0.9, rationale="synthetic"), review_tc(tc))
    return dict(expected={"classification": "needs_engineer_review"}, actual=dict(
        classification=verdict["classification"], status=tc["status"], verification=tc["verification"]["status"],
        issues=tc["verification"]["issues"]))


def scenario_fixture():
    op = dict(name="Get Log Page", raw_opcode="0x02", command_set="ADMIN", opcode="0x02a", section_ref="synthetic")
    structured = dict(description="synthetic", preconditions=[], precondition_checks=[],
                      steps_plan=[dict(opcode_name=op["name"], phase="action", role="read LID 7Eh",
                                       expected_status="INVALID_LOG_PAGE",
                                       field_constraints=[dict(field="cdw10", mask="0xff", value="0x7e")])],
                      requirements=[dict(quote=QUOTE, description="synthetic completion", evidence_id="e",
                                         checks=[dict(kind="completion", step=0)])], out_of_scope=[])
    return op, structured


def malformed_conditions_crash():
    op, structured = scenario_fixture()
    structured.update(preconditions=["some condition"], precondition_checks=["some condition"])
    section = dict(section_id="synthetic", title="synthetic", spec_doc="synthetic")
    rag = dict(chunks=[dict(evidence_id="e", text=QUOTE)], response_id="synthetic")
    with patch.object(scenario_generator, "generate_rag_response", return_value=rag), \
         patch.object(scenario_generator, "generate_llm_response", return_value=dict(structured=structured, response_id="synthetic")):
        try:
            scenario_generator.generate_scenario(section, op, [op], device_support={"lids": {1: True}, "fids": {}})
            error = None
        except Exception as exc:
            error = type(exc).__name__
    return dict(expected={"uncaught_by_pipeline": False}, actual=dict(error=error,
                uncaught_by_pipeline=error == "AttributeError" and AttributeError not in pipeline._LLM_REPLY_ERRORS))


def non_string_precondition_dropped():
    op, structured = scenario_fixture()
    structured["steps_plan"][0]["expected_status"] = "SUCCESS"
    structured["preconditions"] = [{"condition": "controller must be a Discovery controller"}]
    validate_plan_contract(structured, [dict(evidence_id="e", text=QUOTE)], "synthetic", [op])
    action = step(name="Get Log Page", opcode="0x02", cdw10="0x7e", data_len=4, direction="read")
    tc = tc_for([action], requirements=structured["requirements"],
                unmeasured_preconditions=structured["unmeasured_preconditions"])
    tc["scenario"]["preconditions"] = structured["preconditions"]
    execution = dict(step_results=[reply(data=bytes(4))], timed_out=False, dmesg_text="")
    return dict(expected={"status": "UNVERIFIED"}, actual=dict(status=check_expectation(tc, execution),
                remaining_preconditions=structured["preconditions"], unmeasured=structured["unmeasured_preconditions"]))


def rejudge_link():
    with tempfile.TemporaryDirectory(prefix="tc-review-rejudge-") as temp:
        temp = Path(temp)
        fc = make_failure_context(failure_context_id="fc-review", source_type="TC_EXEC", run_id="review",
                                  timestamp="synthetic", primary_log_excerpt="synthetic", signals={})
        save_json_atomic(temp / "failure_contexts" / "tc_exec" / "fc.json", fc)
        tc = dict(tc_for([step()]), failure_context_id=fc["failure_context_id"], verdict_id=None)
        save_json_atomic(temp / "tc_store.json", [tc])
        verdict = dict(verdict_id="verdict-review", failure_context_id=fc["failure_context_id"],
                       classification="needs_engineer_review", confidence=0.5, rationale="synthetic")
        with patch.object(config, "FAILURE_CONTEXTS_DIR", temp / "failure_contexts"), \
             patch.object(config, "VERDICTS_DIR", temp / "verdicts"), \
             patch.object(config, "TC_STORE_PATH", temp / "tc_store.json"), \
             patch.object(run_judge, "judge_failure_context", return_value=verdict):
            run_judge.judge_source("tc_exec")
        tcs = load_json(temp / "tc_store.json")
        verdicts = load_json(temp / "verdicts" / "tc_exec.json")
        linked = {t.get("verdict_id") for t in tcs if t.get("verdict_id")}
        return dict(expected={"current_tc_judgments": 1}, actual=dict(
            current_tc_judgments=sum(v["verdict_id"] in linked for v in verdicts),
            saved_judgments=len(verdicts), tc_verdict_id=tcs[0]["verdict_id"]))


def feature_unsupported_description():
    s = step(name="Get Features", opcode="0x0A", cdw10="0x11", selector_support=False)
    tc = tc_for([s])
    execution = dict(step_results=[reply(error="INVALID_FIELD")], timed_out=False, dmesg_text="")
    tc.update(execution=execution, status=check_expectation(tc, execution), verification=verify_tc(tc, execution))
    text = describe_outcome(tc)["verdict"]
    return dict(expected={"claims_opcode_not_implemented": False}, actual=dict(
        claims_opcode_not_implemented="INVALID_OPCODE" in text, status=tc["status"], description=text,
        actual_completion="INVALID_FIELD"))


def response_id_collision():
    a = json.dumps({"text": "x" * 250 + "first"})
    b = json.dumps({"text": "x" * 250 + "second"})
    with patch.object(llm_client, "_load_guide", return_value=object()), \
         patch.object(llm_client, "_complete", side_effect=[a, b]), \
         patch.object(llm_client, "_append_log"):
        r1 = llm_client.generate_llm_response("same prompt", response_schema={"text": "string"})
        r2 = llm_client.generate_llm_response("same prompt", response_schema={"text": "string"})
    return dict(expected={"distinct_response_ids": True}, actual=dict(
        distinct_response_ids=r1["response_id"] != r2["response_id"], responses_differ=r1["text"] != r2["text"]))


CASES = {
    "R01_permanent_write_protection": irreversible_write_protection,
    "R02a_plm_config_restore_register": lambda: feature_register_restore(0x13, 1, 0, 512),
    "R02b_plm_window_restore_register": lambda: feature_register_restore(0x14, 2, 1, 0),
    "R02c_read_recovery_restore_register": lambda: feature_register_restore(0x12, 7, 3, 0),
    "R02d_timestamp_restore_reserved_bytes": timestamp_restore_payload,
    "R03a_snapshot_missing_cqe": incomplete_snapshot,
    "R03b_snapshot_short_payload": lambda: incomplete_snapshot(payload=True),
    "R04a_retry_changes_namespace": retry_identity,
    "R04b_retry_changes_save_bit": lambda: retry_identity(save=True),
    "R05_host_first_dmesg_scope": host_first_scoping,
    "R05b_host_first_success_log_loss": host_first_success_log_loss,
    "R06_judge_normalization": judge_normalization,
    "R07_unmeasured_premise_defect_verdict": unmeasured_failure,
    "R08a_malformed_conditions_crash": malformed_conditions_crash,
    "R08b_non_string_precondition_dropped": non_string_precondition_dropped,
    "R09_rejudge_unlinked_verdict": rejudge_link,
    "R10_feature_unsupported_description": feature_unsupported_description,
    "R11_response_id_collision": response_id_collision,
}


def main():
    rows = {}
    with patch.object(ssh_runner, "_plink", side_effect=AssertionError("review prohibits real SSH")):
        for name, fn in CASES.items():
            try:
                row = fn()
                row["reproduced"] = any(row["actual"].get(k) != v for k, v in row["expected"].items())
                rows[name] = row
            except Exception as exc:
                rows[name] = dict(reproducer_error=f"{type(exc).__name__}: {exc}")
    print(json.dumps(rows, ensure_ascii=False, indent=2))
    return int(any("reproducer_error" in r for r in rows.values()))


if __name__ == "__main__":
    raise SystemExit(main())
