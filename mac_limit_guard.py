#!/usr/bin/env python3

import ast
import json
import os
import re
import subprocess
import sys
import time
from typing import Dict, List, Tuple, Optional, Any


# ============================================================
# STATIC SCRIPT SETTINGS
# ============================================================

CONFIG_FILE = "/var/db/scripts/mac_limit_guard.conf"

STATE_FILE = "/var/tmp/mac_limit_guard_state.json"
LOCK_FILE = "/var/tmp/mac_limit_guard.lock"
FUNCTION_LOCK_FILE = "/var/tmp/mac_limit_guard.func.lock"

LOG_TAG = "mac_limit_guard"

COMMIT_COMMENT = "Auto-disable logical interfaces: MAC limit exceeded"

# These remain hard-coded safety controls rather than policy.
#
# The interface types the guard is willing to act on: physical ports
# (et-/xe-/ge-) and AE bundles (aeN). An AE is a real customer-facing
# interface - ae3 is the TampaCoOp handoff - and its logical units carry MAC
# limits exactly as a port's do, so it has to be accepted here. Everything
# else (irb, lo0, vtep, esi, ...) is refused rather than guessed at.
#
# Both the policy validation and the MAC-table walk use this, so a type
# missing from it is invisible twice over: the config is rejected outright,
# and even if it were accepted its MACs would never be counted.
ENFORCE_IFD_REGEX = re.compile(
    r"^(?:et-|xe-|ge-)\d+/\d+/\d+$"
    r"|^ae\d+$"
)
IGNORE_IFDS = {"irb", "vtep", "lo0"}


# ============================================================
# COMMAND / LOGGING
# ============================================================

def run_cmd(
    cmd: List[str],
    timeout: int = 20
) -> Tuple[int, str, str]:

    p = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        text=True,
    )

    return p.returncode, p.stdout, p.stderr


def log(msg: str, priority: str = "user.warning") -> None:

    run_cmd([
        "logger",
        "-p", priority,
        "-t", LOG_TAG,
        msg
    ])


# ============================================================
# LOCKING
# ============================================================

def acquire_lock(lockfile: str) -> bool:

    try:
        fd = os.open(
            lockfile,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY
        )

        with os.fdopen(fd, "w") as f:
            f.write(str(os.getpid()))

        return True

    except FileExistsError:
        return False


def release_lock(lockfile: str) -> None:

    try:
        os.remove(lockfile)

    except FileNotFoundError:
        pass


def acquire_script_lock() -> None:

    if not acquire_lock(LOCK_FILE):

        log(
            f"Lockfile exists ({LOCK_FILE}); "
            f"exiting to avoid overlapping script instances",
            "user.notice"
        )

        sys.exit(0)


def acquire_function_lock() -> bool:

    return acquire_lock(FUNCTION_LOCK_FILE)


def release_function_lock() -> None:

    release_lock(FUNCTION_LOCK_FILE)


# ============================================================
# EXTERNAL CONFIGURATION
# ============================================================

ALLOWED_CONFIG_NAMES = {
    "DEFAULT_MAC_LIMIT",
    "RUN_COUNT",
    "RUN_INTERVAL_SECONDS",
    "PER_IFL_LIMIT_EXACT",
    "PER_IFD_LIMIT_EXACT",
    "PER_IFL_LIMIT_REGEX",
    "PER_IFD_LIMIT_REGEX",
}

REQUIRED_CONFIG_NAMES = {
    "DEFAULT_MAC_LIMIT",
    "RUN_COUNT",
    "RUN_INTERVAL_SECONDS",
    "PER_IFL_LIMIT_EXACT",
    "PER_IFD_LIMIT_EXACT",
    "PER_IFL_LIMIT_REGEX",
    "PER_IFD_LIMIT_REGEX",
}


def validate_positive_int(
    value: Any,
    name: str
) -> int:

    # bool is a subclass of int, so explicitly reject it.
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(
            f"{name} must be an integer"
        )

    if value < 1:
        raise ValueError(
            f"{name} must be >= 1"
        )

    return value


def validate_ifd(ifd: str, description: str) -> None:

    if not isinstance(ifd, str):
        raise ValueError(
            f"{description}: interface name must be a string"
        )

    if not ENFORCE_IFD_REGEX.fullmatch(ifd):
        raise ValueError(
            f"{description}: unsupported interface '{ifd}'"
        )


def validate_ifl(ifl: str, description: str) -> None:

    if not isinstance(ifl, str):
        raise ValueError(
            f"{description}: interface name must be a string"
        )

    if "." not in ifl:
        raise ValueError(
            f"{description}: '{ifl}' is not a logical interface"
        )

    ifd, unit = split_ifl(ifl)

    validate_ifd(ifd, description)

    if not unit or not unit.isdigit():
        raise ValueError(
            f"{description}: invalid unit in '{ifl}'"
        )


def parse_config_file() -> Dict[str, Any]:
    """
    Parse the configuration using Python's AST.

    Only simple NAME = literal assignments are permitted.

    This deliberately does NOT exec() the configuration file.
    Therefore arbitrary Python statements/functions/imports cannot
    be executed from the policy file.
    """

    try:

        with open(CONFIG_FILE, "r") as f:
            text = f.read()

    except Exception as e:

        raise RuntimeError(
            f"unable to read {CONFIG_FILE}: {e}"
        )

    try:

        tree = ast.parse(
            text,
            filename=CONFIG_FILE,
            mode="exec"
        )

    except SyntaxError as e:

        raise RuntimeError(
            f"syntax error at line {e.lineno}: {e.msg}"
        )

    config: Dict[str, Any] = {}

    for node in tree.body:

        # Permit a standalone string/documentation block.
        if (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            continue

        if not isinstance(node, ast.Assign):

            raise RuntimeError(
                f"invalid statement at line "
                f"{getattr(node, 'lineno', '?')}; "
                f"only NAME = value assignments are permitted"
            )

        if len(node.targets) != 1:

            raise RuntimeError(
                f"invalid assignment at line {node.lineno}"
            )

        target = node.targets[0]

        if not isinstance(target, ast.Name):

            raise RuntimeError(
                f"invalid assignment target at line {node.lineno}"
            )

        name = target.id

        if name not in ALLOWED_CONFIG_NAMES:

            raise RuntimeError(
                f"unknown configuration option '{name}' "
                f"at line {node.lineno}"
            )

        if name in config:

            raise RuntimeError(
                f"duplicate configuration option '{name}' "
                f"at line {node.lineno}"
            )

        try:

            value = ast.literal_eval(node.value)

        except Exception as e:

            raise RuntimeError(
                f"invalid value for '{name}' "
                f"at line {node.lineno}: {e}"
            )

        config[name] = value

    missing = REQUIRED_CONFIG_NAMES - set(config.keys())

    if missing:

        raise RuntimeError(
            "missing required configuration option(s): "
            + ", ".join(sorted(missing))
        )

    return config


def load_config() -> Dict[str, Any]:
    """
    Load and fully validate the configuration.

    The configuration is returned ONLY if the entire file passes
    validation. Any error causes the caller to fail safe.
    """

    raw = parse_config_file()

    config: Dict[str, Any] = {}

    config["DEFAULT_MAC_LIMIT"] = validate_positive_int(
        raw["DEFAULT_MAC_LIMIT"],
        "DEFAULT_MAC_LIMIT"
    )

    config["RUN_COUNT"] = validate_positive_int(
        raw["RUN_COUNT"],
        "RUN_COUNT"
    )

    config["RUN_INTERVAL_SECONDS"] = validate_positive_int(
        raw["RUN_INTERVAL_SECONDS"],
        "RUN_INTERVAL_SECONDS"
    )

    # --------------------------------------------------------
    # Exact IFL rules
    # --------------------------------------------------------

    if not isinstance(raw["PER_IFL_LIMIT_EXACT"], dict):

        raise RuntimeError(
            "PER_IFL_LIMIT_EXACT must be a dictionary"
        )

    ifl_exact: Dict[str, int] = {}

    for ifl, limit in raw["PER_IFL_LIMIT_EXACT"].items():

        validate_ifl(
            ifl,
            "PER_IFL_LIMIT_EXACT"
        )

        limit = validate_positive_int(
            limit,
            f"PER_IFL_LIMIT_EXACT[{ifl}]"
        )

        ifl_exact[ifl] = limit

    config["PER_IFL_LIMIT_EXACT"] = ifl_exact

    # --------------------------------------------------------
    # Exact IFD rules
    # --------------------------------------------------------

    if not isinstance(raw["PER_IFD_LIMIT_EXACT"], dict):

        raise RuntimeError(
            "PER_IFD_LIMIT_EXACT must be a dictionary"
        )

    ifd_exact: Dict[str, int] = {}

    for ifd, limit in raw["PER_IFD_LIMIT_EXACT"].items():

        validate_ifd(
            ifd,
            "PER_IFD_LIMIT_EXACT"
        )

        limit = validate_positive_int(
            limit,
            f"PER_IFD_LIMIT_EXACT[{ifd}]"
        )

        ifd_exact[ifd] = limit

    config["PER_IFD_LIMIT_EXACT"] = ifd_exact

    # --------------------------------------------------------
    # Regex IFL rules
    # --------------------------------------------------------

    if not isinstance(raw["PER_IFL_LIMIT_REGEX"], list):

        raise RuntimeError(
            "PER_IFL_LIMIT_REGEX must be a list"
        )

    ifl_regex = []

    for index, item in enumerate(
        raw["PER_IFL_LIMIT_REGEX"]
    ):

        if (
            not isinstance(item, tuple)
            or len(item) != 2
        ):

            raise RuntimeError(
                f"PER_IFL_LIMIT_REGEX[{index}] "
                f"must be (regex, limit)"
            )

        pattern_text, limit = item

        if not isinstance(pattern_text, str):

            raise RuntimeError(
                f"PER_IFL_LIMIT_REGEX[{index}] "
                f"regex must be a string"
            )

        limit = validate_positive_int(
            limit,
            f"PER_IFL_LIMIT_REGEX[{index}] limit"
        )

        try:

            pattern = re.compile(pattern_text)

        except re.error as e:

            raise RuntimeError(
                f"PER_IFL_LIMIT_REGEX[{index}] "
                f"invalid regex '{pattern_text}': {e}"
            )

        ifl_regex.append(
            (pattern, limit)
        )

    config["PER_IFL_LIMIT_REGEX"] = ifl_regex

    # --------------------------------------------------------
    # Regex IFD rules
    # --------------------------------------------------------

    if not isinstance(raw["PER_IFD_LIMIT_REGEX"], list):

        raise RuntimeError(
            "PER_IFD_LIMIT_REGEX must be a list"
        )

    ifd_regex = []

    for index, item in enumerate(
        raw["PER_IFD_LIMIT_REGEX"]
    ):

        if (
            not isinstance(item, tuple)
            or len(item) != 2
        ):

            raise RuntimeError(
                f"PER_IFD_LIMIT_REGEX[{index}] "
                f"must be (regex, limit)"
            )

        pattern_text, limit = item

        if not isinstance(pattern_text, str):

            raise RuntimeError(
                f"PER_IFD_LIMIT_REGEX[{index}] "
                f"regex must be a string"
            )

        limit = validate_positive_int(
            limit,
            f"PER_IFD_LIMIT_REGEX[{index}] limit"
        )

        try:

            pattern = re.compile(pattern_text)

        except re.error as e:

            raise RuntimeError(
                f"PER_IFD_LIMIT_REGEX[{index}] "
                f"invalid regex '{pattern_text}': {e}"
            )

        ifd_regex.append(
            (pattern, limit)
        )

    config["PER_IFD_LIMIT_REGEX"] = ifd_regex

    return config


def config_has_policy(config: Dict[str, Any]) -> bool:

    return bool(
        config["PER_IFL_LIMIT_EXACT"]
        or config["PER_IFD_LIMIT_EXACT"]
        or config["PER_IFL_LIMIT_REGEX"]
        or config["PER_IFD_LIMIT_REGEX"]
    )


# ============================================================
# STATE FILE
# ============================================================

def load_state() -> dict:

    try:

        with open(STATE_FILE, "r") as f:
            state = json.load(f)

        if not isinstance(state, dict):
            raise ValueError("state is not an object")

        if not isinstance(
            state.get("disabled_ifls", {}),
            dict
        ):
            raise ValueError(
                "disabled_ifls is not an object"
            )

        return state

    except FileNotFoundError:

        return {
            "disabled_ifls": {},
            "last_run_epoch": 0
        }

    except Exception as e:

        # State errors are also handled conservatively.
        raise RuntimeError(
            f"unable to load state file {STATE_FILE}: {e}"
        )


def save_state(state: dict) -> None:

    tmp = STATE_FILE + ".tmp"

    with open(tmp, "w") as f:

        json.dump(
            state,
            f,
            indent=2,
            sort_keys=True
        )

        f.flush()
        os.fsync(f.fileno())

    os.replace(
        tmp,
        STATE_FILE
    )


# ============================================================
# JUNOS CLI
# ============================================================

def cli_json(command: str) -> dict:

    rc, out, err = run_cmd(
        [
            "cli",
            "-c",
            f"{command} | display json"
        ],
        timeout=25
    )

    if rc != 0:

        raise RuntimeError(
            f"CLI command failed: {command}; "
            f"rc={rc}; error={err.strip()}"
        )

    try:

        return json.loads(out)

    except json.JSONDecodeError as e:

        raise RuntimeError(
            f"failed to decode JSON for "
            f"'{command}': {e}"
        )


def cli_text(
    command: str,
    timeout: int = 25
) -> str:

    rc, out, err = run_cmd(
        ["cli", "-c", command],
        timeout=timeout
    )

    if rc != 0:

        raise RuntimeError(
            f"CLI command failed: {command}; "
            f"rc={rc}; error={err.strip()}"
        )

    return out


# ============================================================
# INTERFACE / POLICY
# ============================================================

def split_ifl(
    ifl: str
) -> Tuple[str, Optional[str]]:

    if "." not in ifl:
        return ifl, None

    ifd, unit = ifl.split(".", 1)

    return ifd, unit


def mac_limit_for_ifl(
    ifl: str,
    config: Dict[str, Any]
) -> Optional[int]:
    """
    Return the limit for an IFL.

    None means the IFL is not included in enforcement.

    Precedence:
      1. Exact IFL
      2. First matching IFL regex
      3. Exact IFD
      4. First matching IFD regex
    """

    ifd, _unit = split_ifl(ifl)

    if ifl in config["PER_IFL_LIMIT_EXACT"]:

        return config[
            "PER_IFL_LIMIT_EXACT"
        ][ifl]

    for pattern, limit in config[
        "PER_IFL_LIMIT_REGEX"
    ]:

        if pattern.search(ifl):
            return limit

    if ifd in config["PER_IFD_LIMIT_EXACT"]:

        return config[
            "PER_IFD_LIMIT_EXACT"
        ][ifd]

    for pattern, limit in config[
        "PER_IFD_LIMIT_REGEX"
    ]:

        if pattern.search(ifd):
            return limit

    return None


# ============================================================
# MAC TABLE PARSING
# ============================================================

def get_text_field(
    d: dict,
    key: str
) -> str:

    v = d.get(key)

    if v is None:
        return ""

    if isinstance(v, str):
        return v

    if isinstance(v, list) and v:

        if (
            isinstance(v[0], dict)
            and "data" in v[0]
        ):

            return str(
                v[0]["data"]
            )

        return str(v[0])

    if (
        isinstance(v, dict)
        and "data" in v
    ):

        return str(v["data"])

    return str(v)


def extract_mac_entries_l2ng(
    j: dict
) -> List[dict]:

    entries: List[dict] = []

    macdb = j.get(
        "l2ng-l2ald-rtb-macdb",
        []
    )

    for db in macdb:

        vlan_blocks = db.get(
            "l2ng-l2ald-mac-entry-vlan",
            []
        )

        for vb in vlan_blocks:

            mac_list = vb.get(
                "l2ng-mac-entry",
                []
            )

            for mac_entry in mac_list:

                entries.append(
                    mac_entry
                )

    return entries


def count_dynamic_macs_per_ifl(
    entries: List[dict],
    config: Dict[str, Any]
) -> Dict[str, int]:
    """
    Count the MACs on each enforced IFL.

    ONLY DYNAMICALLY LEARNED MACs ARE COUNTED. An entry is counted only when
    its flags carry "D"; static entries are ignored. Three things therefore
    never count:

      - a configured `static-mac` (flags "S"), which is how a customer's
        pinned MACs appear
      - a sticky/persistent MAC once it has stuck
      - an EVPN remote entry ("DR"/"DRP"), whose D is qualified by the R

    So a limit bounds what a customer can FLOOD with, not what the segment
    holds. A port carrying only static and sticky MACs can never trip its
    limit, however many of them there are. That is deliberate - the guard
    exists to stop a MAC flood, and static entries are ones we put there
    ourselves - but a limit must not be read as "MACs allowed on this port".

    An entry whose IFD is not matched by ENFORCE_IFD_REGEX is skipped, so an
    interface type missing from that regex is uncountable even if the policy
    naming it was accepted. See the note on that regex.
    """

    counts: Dict[str, int] = {}

    for e in entries:

        mac = get_text_field(
            e,
            "l2ng-l2-mac-address"
        )

        if not mac:
            continue

        flags = get_text_field(
            e,
            "l2ng-l2-mac-flags"
        )

        flag_list = [
            f.strip()
            for f in flags.split(",")
            if f.strip()
        ]

        if "D" not in flag_list:
            continue

        ifl = get_text_field(
            e,
            "l2ng-l2-mac-logical-interface"
        )

        if not ifl:
            continue

        ifd, unit = split_ifl(ifl)

        if ifd in IGNORE_IFDS:
            continue

        if not ENFORCE_IFD_REGEX.fullmatch(ifd):
            continue

        if unit is None:
            continue

        if mac_limit_for_ifl(
            ifl,
            config
        ) is None:
            continue

        counts[ifl] = (
            counts.get(ifl, 0) + 1
        )

    return counts


# ============================================================
# MANUAL RE-ENABLE / STATE HANDLING
# ============================================================

def ifl_admin_is_up(ifl: str) -> bool:

    out = cli_text(
        f"show interfaces terse {ifl} | no-more",
        timeout=20
    )

    for line in out.splitlines():

        line = line.strip()

        if not line:
            continue

        if line.startswith(
            ("Interface", "Physical", "Logical")
        ):
            continue

        if (
            line.startswith(ifl + " ")
            or line == ifl
            or line.startswith(ifl + "\t")
        ):

            parts = line.split()

            if len(parts) >= 2:

                return (
                    parts[1].lower()
                    == "up"
                )

    return False


def scrub_state_for_reenabled_ifls(
    disabled_ifls: dict
) -> dict:

    to_delete = []

    for ifl in list(
        disabled_ifls.keys()
    ):

        try:

            if ifl_admin_is_up(ifl):

                to_delete.append(ifl)

        except Exception as e:

            log(
                f"State check warning for "
                f"{ifl}: {e}",
                "user.notice"
            )

    for ifl in to_delete:

        log(
            f"{ifl} is admin-up again; "
            f"removing from state so "
            f"enforcement resumes",
            "user.notice"
        )

        disabled_ifls.pop(
            ifl,
            None
        )

    return disabled_ifls


# ============================================================
# CONFIGURATION / COMMIT
# ============================================================

def build_commit_comment(
    ifls: List[str]
) -> str:

    comment_targets = ", ".join(
        ifls[:5]
    )

    if len(ifls) > 5:

        comment_targets += (
            f", +{len(ifls) - 5} more"
        )

    return (
        f"{COMMIT_COMMENT} "
        f"({comment_targets})"
    )


def disable_logical_interfaces_batch(
    ifls: List[str]
) -> None:

    if not ifls:
        return

    set_cmds = []

    for ifl in ifls:

        ifd, unit = split_ifl(ifl)

        if unit is None:

            raise RuntimeError(
                f"refusing to disable "
                f"without unit: {ifl}"
            )

        set_cmds.append(
            f"set interfaces {ifd} "
            f"unit {unit} disable"
        )

    cmd_parts = ["configure"]

    cmd_parts.extend(set_cmds)

    cmd_parts.append(
        f'commit comment '
        f'"{build_commit_comment(ifls)}"'
    )

    cmd_parts.append("exit")

    cmd = "; ".join(
        cmd_parts
    )

    rc, out, err = run_cmd(
        ["cli", "-c", cmd],
        timeout=120
    )

    if rc != 0:

        error_text = (
            err.strip()
            or out.strip()
            or "unknown commit error"
        )

        raise RuntimeError(
            f"rc={rc}: {error_text}"
        )

    log(
        f"Disabled {len(ifls)} "
        f"logical interface(s) in "
        f"a single commit: "
        f"{', '.join(ifls)}",
        "user.warning"
    )


def disable_single_logical_interface(
    ifl: str
) -> None:

    ifd, unit = split_ifl(ifl)

    if unit is None:

        raise RuntimeError(
            f"refusing to disable "
            f"without unit: {ifl}"
        )

    cmd = (
        f"configure; "
        f"set interfaces {ifd} "
        f"unit {unit} disable; "
        f'commit comment '
        f'"{COMMIT_COMMENT} ({ifl})"; '
        f"exit"
    )

    rc, out, err = run_cmd(
        ["cli", "-c", cmd],
        timeout=90
    )

    if rc != 0:

        error_text = (
            err.strip()
            or out.strip()
            or "unknown commit error"
        )

        raise RuntimeError(
            f"rc={rc}: {error_text}"
        )


def disable_with_batch_then_fallback(
    pending_ifls: List[str],
    pending_meta: Dict[
        str,
        Dict[str, int]
    ]
) -> Dict[str, Dict[str, int]]:

    successful_meta = {}

    if not pending_ifls:
        return successful_meta

    # Normal case: one commit.
    try:

        disable_logical_interfaces_batch(
            pending_ifls
        )

        successful_meta.update(
            pending_meta
        )

        return successful_meta

    except Exception as e:

        log(
            f"Batch disable commit FAILED "
            f"for {len(pending_ifls)} "
            f"interface(s): "
            f"{', '.join(pending_ifls)}; "
            f"error: {e}. "
            f"Attempting individual commits.",
            "user.err"
        )

    # Exceptional fallback path.
    for ifl in pending_ifls:

        try:

            disable_single_logical_interface(
                ifl
            )

            successful_meta[ifl] = (
                pending_meta[ifl]
            )

            log(
                f"Fallback individual disable "
                f"SUCCEEDED for {ifl}",
                "user.warning"
            )

        except Exception as e:

            log(
                f"Fallback individual disable "
                f"FAILED for {ifl}: {e}",
                "user.err"
            )

    return successful_meta


# ============================================================
# ENFORCEMENT PASS
# ============================================================

def enforce_once(
    iteration_num: int,
    scheduled_start: float
) -> None:

    actual_start = time.time()

    drift = (
        actual_start
        - scheduled_start
    )

    if drift > 0.5:

        log(
            f"Iteration {iteration_num}: "
            f"starting {drift:.1f}s later "
            f"than scheduled",
            "user.notice"
        )

    # --------------------------------------------------------
    # Load fresh policy.
    #
    # IMPORTANT:
    # If ANY part of the configuration is invalid,
    # this pass performs NO enforcement.
    # --------------------------------------------------------

    try:

        config = load_config()

    except Exception as e:

        log(
            f"Iteration {iteration_num}: "
            f"CONFIGURATION INVALID: {e}; "
            f"FAIL-SAFE: no interfaces will "
            f"be disabled during this pass",
            "user.err"
        )

        return

    if not config_has_policy(config):

        log(
            f"Iteration {iteration_num}: "
            f"no interface policy configured; "
            f"no enforcement performed",
            "user.notice"
        )

        return

    # --------------------------------------------------------
    # State
    # --------------------------------------------------------

    try:

        state = load_state()

    except Exception as e:

        log(
            f"Iteration {iteration_num}: "
            f"STATE ERROR: {e}; "
            f"FAIL-SAFE: no interfaces will "
            f"be disabled during this pass",
            "user.err"
        )

        return

    disabled_ifls = state.get(
        "disabled_ifls",
        {}
    )

    disabled_ifls = (
        scrub_state_for_reenabled_ifls(
            disabled_ifls
        )
    )

    state["disabled_ifls"] = (
        disabled_ifls
    )

    # --------------------------------------------------------
    # MAC table
    # --------------------------------------------------------

    try:

        j = cli_json(
            "show ethernet-switching table"
        )

        entries = (
            extract_mac_entries_l2ng(j)
        )

        counts = (
            count_dynamic_macs_per_ifl(
                entries,
                config
            )
        )

    except Exception as e:

        log(
            f"Iteration {iteration_num}: "
            f"MAC table processing FAILED: "
            f"{e}; FAIL-SAFE: no interfaces "
            f"will be disabled during this pass",
            "user.err"
        )

        return

    # --------------------------------------------------------
    # Determine violations
    # --------------------------------------------------------

    offenders: List[
        Tuple[str, int, int]
    ] = []

    for ifl, count in counts.items():

        limit = mac_limit_for_ifl(
            ifl,
            config
        )

        if limit is None:
            continue

        if count > limit:

            offenders.append(
                (
                    ifl,
                    count,
                    limit
                )
            )

    offenders.sort(
        key=lambda x: x[1],
        reverse=True
    )

    # --------------------------------------------------------
    # Build batch
    # --------------------------------------------------------

    if offenders:

        pending_ifls = []

        pending_meta = {}

        now_epoch = int(
            time.time()
        )

        for (
            ifl,
            count,
            limit
        ) in offenders:

            if ifl in disabled_ifls:
                continue

            log(
                f"MAC limit exceeded on "
                f"{ifl}: learned {count} "
                f"MACs (limit {limit}). "
                f"Queuing logical interface "
                f"for batch disable.",
                "user.warning"
            )

            pending_ifls.append(
                ifl
            )

            pending_meta[ifl] = {
                "disabled_epoch": now_epoch,
                "mac_count_at_disable": count,
                "limit": limit,
            }

        if pending_ifls:

            successful_meta = (
                disable_with_batch_then_fallback(
                    pending_ifls,
                    pending_meta
                )
            )

            disabled_ifls.update(
                successful_meta
            )

    # --------------------------------------------------------
    # Save state
    # --------------------------------------------------------

    state["disabled_ifls"] = (
        disabled_ifls
    )

    state["last_run_epoch"] = int(
        time.time()
    )

    try:

        save_state(state)

    except Exception as e:

        log(
            f"Iteration {iteration_num}: "
            f"WARNING: unable to save "
            f"state file: {e}",
            "user.err"
        )


# ============================================================
# SCHEDULER
# ============================================================

def scheduler_loop() -> int:

    # Scheduler settings are established when the
    # process starts.
    try:

        startup_config = load_config()

    except Exception as e:

        log(
            f"Unable to start: "
            f"CONFIGURATION INVALID: {e}; "
            f"FAIL-SAFE: no enforcement performed",
            "user.err"
        )

        return 1

    if not config_has_policy(
        startup_config
    ):

        log(
            "No interface policy configured; "
            "nothing to enforce",
            "user.notice"
        )

        return 0

    run_count = (
        startup_config["RUN_COUNT"]
    )

    interval = (
        startup_config[
            "RUN_INTERVAL_SECONDS"
        ]
    )

    initial_start = time.time()

    log(
        f"Starting scheduler loop: "
        f"run_count={run_count}, "
        f"interval={interval}s",
        "user.notice"
    )

    for i in range(run_count):

        scheduled_start = (
            initial_start
            + (i * interval)
        )

        sleep_for = (
            scheduled_start
            - time.time()
        )

        if sleep_for > 0:
            time.sleep(sleep_for)

        # Because this scheduler executes synchronously,
        # an earlier pass that overruns naturally delays
        # this pass. Log that condition explicitly.

        now = time.time()

        overrun = (
            now - scheduled_start
        )

        if overrun > 0.5:

            log(
                f"Iteration {i + 1}: "
                f"previous processing overran "
                f"scheduled start by "
                f"{overrun:.1f}s; "
                f"starting deferred run now",
                "user.notice"
            )

        # Retain function lock as an additional
        # protection against unexpected contention.

        wait_start = time.time()
        lock_wait_logged = False

        while not acquire_function_lock():

            if not lock_wait_logged:

                log(
                    f"Iteration {i + 1}: "
                    f"enforcement lock is busy; "
                    f"postponing until lock clears",
                    "user.notice"
                )

                lock_wait_logged = True

            time.sleep(0.5)

        try:

            if lock_wait_logged:

                waited = (
                    time.time()
                    - wait_start
                )

                log(
                    f"Iteration {i + 1}: "
                    f"enforcement lock cleared "
                    f"after {waited:.1f}s; "
                    f"starting deferred run",
                    "user.notice"
                )

            try:

                enforce_once(
                    i + 1,
                    scheduled_start
                )

            except Exception as e:

                log(
                    f"Iteration {i + 1}: "
                    f"unexpected enforcement "
                    f"failure: {e}",
                    "user.err"
                )

        finally:

            release_function_lock()

    log(
        "Scheduler loop completed",
        "user.notice"
    )

    return 0


# ============================================================
# MAIN
# ============================================================

def main() -> int:

    acquire_script_lock()

    try:

        return scheduler_loop()

    finally:

        release_lock(
            LOCK_FILE
        )

        release_function_lock()


if __name__ == "__main__":
    sys.exit(main())

