"""Offline review of the latest fixes. No device, SSH, or LLM calls."""
import json
from pathlib import Path
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
import config
from tc_system.execution import ssh_runner
from tc_system.execution.expectation_checker import check_expectation
from tc_system.generation.variants import RULES
from tc_system.verification import validate_plan_contract, verify_tc
from tests.test_deep_review import step, reply, tc_for, with_restore, run


def error_after_change():
    """Fault injection: the controller changes the value then reports INTERNAL.
    An internal failure is not proof that an operation was rejected before
    applying it. The harness should not assert that nothing changed.
    """
    state = {"value": 360}
    tc = with_restore(step(cdw10="0x04", cdw11="0x12c"))

    def device(s):
        if int(s["opcode"], 16) == 10:
            return reply(state["value"])
        state["value"] = int(s["cdw11"], 16)
        return reply(error="INTERNAL") if s["phase"] == "action" else reply()

    e, sent = run(tc, device)
    return dict(expected_final_value=360, actual_final_value=state["value"],
                commands=[(s["phase"], s["name"]) for s in sent], cleanup=e["step_results"][-1],
                reproduced=state["value"] != 360)


def fid_plan(description):
    q = RULES["reserved_fid"][1]
    ops = [dict(name="Get Log Page", raw_opcode="0x02", command_set="ADMIN", opcode="0x02a"),
           dict(name="Get Features", raw_opcode="0x0A", command_set="ADMIN", opcode="0x0Aa")]
    plan = dict(description="synthetic", preconditions=[description], out_of_scope=[],
                precondition_checks=[dict(description=description, checks=[
                    dict(kind="data_field", step=0, field="FSUPP", index="7Fh", value=0)])],
                steps_plan=[dict(opcode_name="Get Log Page", phase="setup", expected_status="SUCCESS",
                                 field_constraints=[dict(field="cdw10", mask="0xff", value="0x12")]),
                            dict(opcode_name="Get Features", phase="action", expected_status="INVALID_FIELD",
                                 field_constraints=[dict(field="cdw10", mask="0x7ff", value="0x7f")])],
                requirements=[dict(description="unsupported FID must be rejected", quote=q, evidence_id="e",
                                   checks=[dict(kind="completion", step=1)])])
    validate_plan_contract(plan, [dict(evidence_id="e", text=q)], "s", ops,
                           device_support={"lids": {}, "fids": {1: True}})
    setup = step(name="Get Log Page", phase="setup", opcode="0x02", cdw10="0x00ff0012", cdw11="0x0",
                 data_len=1024, direction="read")
    action = step(name="Get Features", opcode="0x0A", cdw10="0x7f", cdw11="0x0", data_len=0,
                  direction="none", expected_status="INVALID_FIELD")
    tc = tc_for([setup, action], requirements=plan["requirements"],
                precondition_checks=plan["precondition_checks"], evidence=[dict(evidence_id="e", text=q)],
                unmeasured_preconditions=plan["unmeasured_preconditions"])
    tc["scenario"]["preconditions"] = plan["preconditions"]
    e = dict(step_results=[dict(reply(data=bytes(1024)), step_index=0), dict(reply(), step_index=1)])
    return plan, tc, e


def measured_fid_marked_unmeasured():
    plan, tc, e = fid_plan("FID 7Fh 미지원")
    v = verify_tc(tc, e)
    status = check_expectation(tc, e)
    return dict(expected_status="FAIL", actual_status=status,
                precondition=v["preconditions"][0]["results"][0]["result"],
                requirement_check=v["requirements"][0]["results"][0]["result"],
                unmeasured=plan["unmeasured_preconditions"], reproduced=status != "FAIL")


def unsupported_polarity_reversed():
    plan, tc, e = fid_plan("FID 7Fh is unsupported")
    check = plan["precondition_checks"][0]["checks"][0]
    value = int(str(check["value"]), 0)
    return dict(expected_support_bit=0, actual_support_bit=value,
                repairs=plan.get("check_repairs"), reproduced=value != 0)


if __name__ == "__main__":
    with patch.object(config, "get_ssh_target", side_effect=AssertionError("real target access prohibited")), \
         patch.object(ssh_runner, "_plink", side_effect=AssertionError("real SSH prohibited")):
        result = {name: fn() for name, fn in {
            "N01_error_after_change": error_after_change,
            "N02_measured_fid_marked_unmeasured": measured_fid_marked_unmeasured,
            "N03_unsupported_polarity_reversed": unsupported_polarity_reversed,
        }.items()}
    print(json.dumps(result, ensure_ascii=False, indent=2))
