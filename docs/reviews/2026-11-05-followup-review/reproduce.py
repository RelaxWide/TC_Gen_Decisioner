"""Offline follow-up counterexamples for the revised contracts (504 tests).

No product code is modified. Uses the reviewed regression fixtures and mocks
every execution boundary; stdout is the only persistent output.
"""
import json
from pathlib import Path
import re
import sys
import tempfile
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
import config
from report.aggregator import build_tc_model
from report.html_report import _progress_section
from shared.file_store import save_json_atomic
from tc_system.execution import ssh_runner
from tc_system.execution.expectation_checker import check_expectation
from tc_system.review import review_tc
from tc_system.verification import payload_for_step, validate_plan_contract, verify_tc
from tests.test_deep_review import reply, run, step, tc_for, with_restore


def interrupt_during_change():
    tc = with_restore(step(cdw10="0x04", cdw11="0x12c"))
    state, calls = {"value": 360}, []

    def device(s):
        calls.append((s["phase"], s["name"]))
        if int(s["opcode"], 16) == 10:
            return reply(state["value"])
        state["value"] = int(s["cdw11"], 16)
        if s["phase"] == "action":
            raise KeyboardInterrupt()
        return reply()

    try:
        run(tc, device)
    except KeyboardInterrupt:
        pass
    return dict(expected_value=360, actual_value=state["value"], calls=calls,
                reproduced=state["value"] != 360)


def unrelated_support_measurement():
    q = ("If a Get Log Page command specifies a Log Page Identifier that is not supported, then the "
         "controller shall abort the command with a status code of Invalid Log Page.")
    ops = [dict(name="Get Log Page", raw_opcode="0x02", command_set="ADMIN", opcode="0x02a")]
    plan = dict(description="synthetic", preconditions=["LID 00h is supported"], out_of_scope=[],
                precondition_checks=[dict(description="LID 00h is supported", checks=[
                    dict(kind="data_field", step=0, field="LSUPP", index=0, value=1)])],
                steps_plan=[dict(opcode_name="Get Log Page", phase="setup", expected_status="SUCCESS",
                                 field_constraints=[dict(field="cdw10", mask="0xff", value="0x00")]),
                            dict(opcode_name="Get Log Page", phase="action", expected_status="INVALID_LOG_PAGE",
                                 field_constraints=[dict(field="cdw10", mask="0xff", value="0x7e")])],
                requirements=[dict(description="unsupported LID must abort", quote=q, evidence_id="e",
                                   checks=[dict(kind="completion", step=1)])])
    try:
        validate_plan_contract(plan, [dict(evidence_id="e", text=q)], "s", ops,
                               device_support={"lids": {0: True}, "fids": {}})
    except ValueError as exc:
        return dict(actual_status="PLAN_REJECTED", reason=str(exc), reproduced=False)
    setup = step(name="Get Log Page", phase="setup", opcode="0x02", cdw10="0x00ff0000",
                 data_len=1024, direction="read")
    action = step(name="Get Log Page", phase="action", opcode="0x02", cdw10="0x007f007e",
                  data_len=512, direction="read", expected_status="INVALID_LOG_PAGE")
    tc = tc_for([setup, action], requirements=plan["requirements"], evidence=[dict(evidence_id="e", text=q)],
                precondition_checks=plan["precondition_checks"],
                unmeasured_preconditions=plan["unmeasured_preconditions"])
    tc["scenario"]["preconditions"] = plan["preconditions"]
    e = dict(step_results=[dict(reply(data=b"\x01" + bytes(1023)), step_index=0),
                           dict(reply(data=bytes(512)), step_index=1)])
    status = check_expectation(tc, e)
    return dict(expected="do not assert a violation of an unmeasured unsupported premise", actual_status=status,
                unmeasured=plan["unmeasured_preconditions"], reproduced=status == "FAIL")


def host_identifier_transition():
    tc = with_restore(step(cdw10="0x81", cdw11="0x0", nsid=0, data_len=8,
                           direction="write", payload_hex="ab"))
    state = {"hostid": bytes(8)}

    def device(s):
        if int(s["opcode"], 16) == 10:
            return reply(0, state["hostid"])
        if any(state["hostid"]):
            return reply(error="CMD_SEQ_ERROR")
        state["hostid"] = payload_for_step(s)
        return reply()

    e, sent = run(tc, device)
    return dict(expected_hostid=bytes(8).hex(), actual_hostid=state["hostid"].hex(),
                cleanup=e["step_results"][-1]["stdout"], tc_status=check_expectation(tc, e),
                reproduced=any(state["hostid"]))


def failed_readback_review():
    state = {"value": 360, "reads": 0}
    tc = with_restore(step(cdw10="0x04", cdw11="0x12c"))

    def device(s):
        if int(s["opcode"], 16) == 10:
            state["reads"] += 1
            return reply(state["value"]) if state["reads"] == 1 else reply(error="INTERNAL")
        if s["phase"] == "action":
            state["value"] = int(s["cdw11"], 16)
        # A cleanup ACK is insufficient proof; its readback then fails.
        return reply()

    e, sent = run(tc, device)
    tc.update(execution=e, status=check_expectation(tc, e), verification=verify_tc(tc, e))
    review = review_tc(tc)
    return dict(expected="request review when a restore cannot be confirmed", actual_level=review["level"],
                actual_status=tc["status"], reasons=review["reasons"], reproduced=review["level"] == "info")


def skipped_only_latest_run():
    old, latest = "20261105T010000Z", "20261105T020000Z"
    with tempfile.TemporaryDirectory(prefix="tc-followup-review-") as temp:
        p = Path(temp)
        tc = dict(tc_for([step(name="Get Features", opcode="0x0A")]), run_id=old, status="PASS",
                  execution=dict(step_results=[reply()]))
        save_json_atomic(p / "tc_store.json", [tc])
        save_json_atomic(p / "target_skips.json", [dict(run_id=latest, section_id="s", opcode="0x0Aa",
                                                       reason="synthetic generation failure")])
        save_json_atomic(p / "manifests" / f"{latest}.json", dict(run_id=latest))
        with patch.multiple(config, TC_STORE_PATH=p / "tc_store.json", TARGET_SKIPS_PATH=p / "target_skips.json",
                            COVERAGE_STATE_PATH=p / "coverage.json", FAILURE_CONTEXTS_DIR=p / "fcs",
                            VERDICTS_DIR=p / "verdicts", RUN_MANIFESTS_DIR=p / "manifests"), \
             patch.object(config, "active_coverage_index_path", return_value=p / "missing_index.json"):
            model = build_tc_model()
        text = re.sub("<[^>]+>", " ", _progress_section(model["tc_records"], model["skips"], model["run_id"]))
        return dict(expected_run_id=latest, actual_run_id=model["run_id"], actual_progress=text,
                    reproduced=model["run_id"] != latest)


if __name__ == "__main__":
    with patch.object(config, "get_ssh_target", side_effect=AssertionError("real target access prohibited")), \
         patch.object(ssh_runner, "_plink", side_effect=AssertionError("real SSH prohibited")):
        result = {name: fn() for name, fn in {
            "F01_interrupt_during_change": interrupt_during_change,
            "F02_unrelated_support_measurement": unrelated_support_measurement,
            "F03_host_identifier_transition": host_identifier_transition,
            "F04_failed_readback_review": failed_readback_review,
            "F05_skipped_only_latest_run": skipped_only_latest_run,
        }.items()}
    print(json.dumps(result, ensure_ascii=False, indent=2))
