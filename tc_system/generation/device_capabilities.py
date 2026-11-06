"""Formats a Korean-language hint block, read directly from the real target's
own self-reported capabilities, that gets spliced into scenario/arg-authoring
prompts so the model stops proposing commands/values this specific drive is
already known (via one probe at the start of a run — see
`tc_system.execution.ssh_runner.probe_device_capabilities`) not to support —
instead of spending an LLM call plus an SSH round trip to rediscover the same
answer empirically for every target. Measured against `data/tc_store.json`:
UNSUPPORTED was the single largest outcome bucket (54/103 TCs, ~52%).

Every lookup here is best-effort: an unparseable or missing field just drops
its line from the summary instead of raising. A failed probe, or an nvme-cli
version missing a subcommand (`effects-log` in particular), must never block
generation — this was only ever meant to make it faster, never a precondition
for it to run at all.
"""
import re

_FIELD_RE = re.compile(r"^\s*([a-z][a-z0-9_]*)\s*:\s*(\S+)", re.M)
_EFFECTS_RE = re.compile(r"^\s*(?:ACS|IOCS)\s+\d+\s*\(([^)]+)\)\s+CSUPP\+", re.M)
_LBA_IN_USE_RE = re.compile(r"Data Size:\s*(\d+)\s*bytes.*\(in use\)")

# NVMe Base Specification, Identify Controller data structure.
_OACS_BITS = {
    0: "Security Send/Receive", 1: "Format NVM", 2: "Firmware Commit/Download",
    3: "Namespace Management", 4: "Device Self-test", 5: "Directives",
    6: "NVMe-MI Send/Receive", 7: "Virtualization Management",
    8: "Doorbell Buffer Config", 9: "Get LBA Status",
}
_ONCS_BITS = {
    0: "Compare", 1: "Write Uncorrectable", 2: "Dataset Management", 3: "Write Zeroes",
    4: "Save/Select Feature", 5: "Reservations", 6: "Timestamp", 7: "Verify", 8: "Copy",
}
_SANICAP_BITS = {0: "Crypto Erase", 1: "Block Erase", 2: "Overwrite"}


def _parse_fields(raw: str) -> dict[str, str]:
    return dict(_FIELD_RE.findall(raw or ""))


def _as_int(value: str | None) -> int | None:
    if not value:
        return None
    try:
        return int(value, 16) if value.lower().startswith("0x") else int(value)
    except ValueError:
        return None


def _decode_bitmask(value: str | None, bit_names: dict[int, str]) -> list[str]:
    n = _as_int(value)
    if n is None:
        return []
    return [name for bit, name in bit_names.items() if n & (1 << bit)]


def _parse_effects_log(raw: str) -> list[str]:
    return _EFFECTS_RE.findall(raw or "")


# FIDs whose support is probed with Get Features SEL=011b at the start of a run.
PROBED_FIDS = list(range(0x01, 0x25)) + [0x7D, 0x7E, 0x7F] + list(range(0x80, 0x86))
_FID_BLOCK_RE = re.compile(r"FID=([0-9A-Fa-f]{2})\r?\n(.*?)RC=(\d+)", re.S)


def device_support(raw: dict[str, str] | None) -> dict:
    """{"lids": {lid: bool}, "fids": {fid: bool}} from the probe; an id that
    was not answered is simply absent (unknown), never assumed either way."""
    from tc_system.verification import decode_payload
    raw = raw or {}
    support = {"lids": {}, "fids": {}}
    data = decode_payload({"stdout": raw.get("supported_logs", "")})
    if data is not None and len(data) >= 1024:
        support["lids"] = {lid: bool(data[lid * 4] & 1) for lid in range(256)}
    for fid, out, rc in _FID_BLOCK_RE.findall(raw.get("fid_support", "") or ""):
        if rc == "0":
            support["fids"][int(fid, 16)] = True
        elif out.count("INVALID_FIELD") >= (2 if "NSID_RETRY" in out else 1):
            support["fids"][int(fid, 16)] = False
    # SEL=011b is itself an invalid field on a drive without Save/Select
    # (ONCS bit 4): then every FID answers INVALID_FIELD and proves nothing.
    # Arbitration (01h) is mandatory, so its rejection means the same.
    oncs = _as_int(_parse_fields(raw.get("id_ctrl", "")).get("oncs"))
    if (oncs is not None and not oncs & 0x10) or support["fids"].get(0x01) is False:
        support["fids"] = {}
    return support


def host_versions(raw: dict[str, str] | None) -> dict:
    text = (raw or {}).get("host_versions", "") or ""
    nvme = re.search(r"nvme version\s+(\S+)", text)
    kernel = next((l.strip() for l in text.splitlines() if re.match(r"^\d+\.\d+", l.strip())), None)
    ctrl = _parse_fields((raw or {}).get("id_ctrl", ""))
    return {"nvme_cli": nvme.group(1) if nvme else None, "kernel": kernel,
            "model": ctrl.get("mn"), "firmware": ctrl.get("fr")}


def namespace_size(raw: dict[str, str] | None) -> int | None:
    """NSZE (logical blocks) from `nvme id-ns`, or None."""
    return _as_int(_parse_fields((raw or {}).get("id_ns", "")).get("nsze"))


def in_use_lba_bytes(raw: dict[str, str] | None) -> int | None:
    """LBA data size of the namespace's in-use format, or None if unknown."""
    match = _LBA_IN_USE_RE.search((raw or {}).get("id_ns", "") or "")
    return int(match.group(1)) if match else None


def summarize_device_capabilities(raw: dict[str, str]) -> str:
    """`raw` is the dict `ssh_runner.probe_device_capabilities` returns
    (`{"id_ctrl": <text>, "id_ns": <text>, "effects_log": <text>}`, any of
    which may be missing or empty). Returns "" — never None, never raises —
    when nothing in it was parseable, so callers can treat the result as a
    plain falsy "no hint available"."""
    lines = []

    ctrl_fields = _parse_fields((raw or {}).get("id_ctrl", ""))
    oacs = _decode_bitmask(ctrl_fields.get("oacs"), _OACS_BITS)
    if oacs:
        lines.append(f"지원하는 optional admin 커맨드(OACS): {', '.join(oacs)}")
    oncs = _decode_bitmask(ctrl_fields.get("oncs"), _ONCS_BITS)
    if oncs:
        lines.append(f"지원하는 optional NVM 커맨드(ONCS): {', '.join(oncs)}")
    sanicap = _decode_bitmask(ctrl_fields.get("sanicap"), _SANICAP_BITS)
    if sanicap:
        lines.append(f"Sanitize 지원 방식(SANICAP): {', '.join(sanicap)}")
    npss = _as_int(ctrl_fields.get("npss"))
    if npss is not None:
        lines.append(f"지원하는 Power State 번호 범위: 0~{npss} (NPSS={npss})")
    mdts = _as_int(ctrl_fields.get("mdts"))
    if mdts is not None:
        lines.append(f"MDTS(최대 전송 크기 필드, raw)={mdts} — 0이면 명시된 상한 없음, "
                      "그 외엔 전송 길이를 작게(512~4096B) 유지할 것")

    ns_fields = _parse_fields((raw or {}).get("id_ns", ""))
    nsze = _as_int(ns_fields.get("nsze"))
    if nsze is not None:
        lines.append(f"네임스페이스 크기(NSZE)=0x{nsze:X} LBA — LBA는 이 범위 안에서만 유효함")
    lba_match = _LBA_IN_USE_RE.search((raw or {}).get("id_ns", "") or "")
    if lba_match:
        lines.append(f"현재 사용 중인 LBA 포맷의 섹터 크기={lba_match.group(1)} bytes")

    support = device_support(raw)
    if support["lids"]:
        lids = [f"{lid:02X}h" for lid, ok in sorted(support["lids"].items()) if ok]
        lines.append("Supported Log Pages(LID 00h)로 실측된 지원 LID: " + ", ".join(lids)
                     + " — 이 밖의 LID는 이 드라이브가 지원하지 않음")
    if support["fids"]:
        yes = [f"{f:02X}h" for f, ok in sorted(support["fids"].items()) if ok]
        no = [f"{f:02X}h" for f, ok in sorted(support["fids"].items()) if not ok]
        lines.append(f"Get Features SEL=011b로 실측된 지원 FID: {', '.join(yes) or '없음'}; "
                     f"미지원 FID(INVALID_FIELD): {', '.join(no) or '없음'}")

    supported_opcodes = _parse_effects_log((raw or {}).get("effects_log", ""))
    if supported_opcodes:
        lines.append("Commands Supported and Effects 로그로 실측된 지원 커맨드: "
                      + ", ".join(sorted(set(supported_opcodes))))

    if not lines:
        return ""
    return ("이 드라이브에서 직접 조회한 실제 역량입니다(스펙 일반론이 아니라 이 타겟 자체의 값):\n"
            + "\n".join(f"- {l}" for l in lines))
