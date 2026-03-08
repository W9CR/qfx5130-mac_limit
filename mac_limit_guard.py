#!/usr/bin/env python3
#
# Mac Limit event script for Juniper QFX5130 router
#
# Copyright 2026 Bryan Fields bryan@bryanfields.net
#
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
# 
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>
#
import json
import os
import re
import subprocess
import sys
import time
from typing import Dict, List, Tuple, Optional

# ====== SCHEDULER OPTIONS ======
# Run the enforcement function this many times per script invocation.
RUN_COUNT = 4

# Run every N seconds, measured from scheduled start time, not completion time.
RUN_INTERVAL_SECONDS = 15
# ===============================

# ====== DEFAULTS ======
DEFAULT_MAC_LIMIT = 2

# Enforce only on these physical interface patterns (adjust as needed)
ENFORCE_IFD_REGEX = re.compile(r"^(et-|xe-|ge-)\d+/\d+/\d+$")

# ====== INCLUDE-ONLY POLICY ======
# If an interface/unit does NOT match one of these, it is ignored.
# You can include by IFL (et-0/0/46.2645) or by IFD (et-0/0/46 -> all units).

INCLUDE_IFLS_EXACT = {
    # "et-0/0/46.2645",
}
INCLUDE_IFLS_REGEX = [
    # re.compile(r"^et-0/0/46\.(2420|2645)$"),
]

INCLUDE_IFDS_EXACT = {
    # "et-0/0/46",
}
INCLUDE_IFDS_REGEX = [
    # re.compile(r"^et-0/0/4[0-7]$"),
]

# ====== PER-IFL/IFD LIMITS ======
# Most specific (IFL) overrides IFD, else DEFAULT_MAC_LIMIT.

PER_IFL_LIMIT_EXACT: Dict[str, int] = {
    # "et-0/0/46.2645": 2,
}
PER_IFL_LIMIT_REGEX: List[Tuple[re.Pattern, int]] = [
    # (re.compile(r"^et-0/0/46\.\d+$"), 2),
]

PER_IFD_LIMIT_EXACT: Dict[str, int] = {
    # "et-0/0/46": 2,
}
PER_IFD_LIMIT_REGEX: List[Tuple[re.Pattern, int]] = [
    # (re.compile(r"^et-0/0/4\d$"), 2),
]
# =====================

# Ignore these outright (non-port interfaces)
IGNORE_IFDS = {"irb", "vtep", "lo0"}

STATE_FILE = "/var/tmp/mac_limit_guard_state.json"
LOCK_FILE = "/var/tmp/mac_limit_guard.lock"                   # whole-script lock
FUNCTION_LOCK_FILE = "/var/tmp/mac_limit_guard.func.lock"    # per-iteration lock
LOG_TAG = "mac_limit_guard"
COMMIT_COMMENT = "Auto-disable logical interfaces: MAC limit exceeded"


def run_cmd(cmd: List[str], timeout: int = 20) -> Tuple[int, str, str]:
    p = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        text=True,
    )
    return p.returncode, p.stdout, p.stderr


def log(msg: str, priority: str = "user.warning") -> None:
    run_cmd(["logger", "-p", priority, "-t", LOG_TAG, msg])


def acquire_lock(lockfile: str, exit_on_fail: bool = False, log_on_fail: bool = False) -> bool:
    try:
        fd = os.open(lockfile, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        with os.fdopen(fd, "w") as f:
            f.write(str(os.getpid()))
        return True
    except FileExistsError:
        if log_on_fail:
            log(f"Lockfile exists ({lockfile})", "user.notice")
        if exit_on_fail:
            sys.exit(0)
        return False


def release_lock(lockfile: str) -> None:
    try:
        os.remove(lockfile)
    except FileNotFoundError:
        pass


def acquire_script_lock() -> None:
    if not acquire_lock(LOCK_FILE, exit_on_fail=False, log_on_fail=False):
        log(f"Lockfile exists ({LOCK_FILE}); exiting to avoid overlapping script instances", "user.notice")
        sys.exit(0)


def acquire_function_lock() -> bool:
    return acquire_lock(FUNCTION_LOCK_FILE, exit_on_fail=False, log_on_fail=False)


def release_function_lock() -> None:
    release_lock(FUNCTION_LOCK_FILE)


def load_state() -> dict:
    try:
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {"disabled_ifls": {}, "last_run_epoch": 0}


def save_state(state: dict) -> None:
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f, indent=2, sort_keys=True)
    os.replace(tmp, STATE_FILE)


def cli_json(command: str) -> dict:
    rc, out, err = run_cmd(["cli", "-c", f"{command} | display json"], timeout=25)
    if rc != 0:
        raise RuntimeError(f"CLI command failed: {command} rc={rc} err={err.strip()}")
    try:
        return json.loads(out)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Failed to decode JSON for command: {command}: {e}")


def cli_text(command: str, timeout: int = 25) -> str:
    rc, out, err = run_cmd(["cli", "-c", command], timeout=timeout)
    if rc != 0:
        raise RuntimeError(f"CLI command failed: {command} rc={rc} err={err.strip()}")
    return out


def get_text_field(d: dict, key: str) -> str:
    v = d.get(key)
    if v is None:
        return ""
    if isinstance(v, str):
        return v
    if isinstance(v, list) and v:
        if isinstance(v[0], dict) and "data" in v[0]:
            return str(v[0]["data"])
        return str(v[0])
    if isinstance(v, dict) and "data" in v:
        return str(v["data"])
    return str(v)


def split_ifl(ifl: str) -> Tuple[str, Optional[str]]:
    if "." not in ifl:
        return ifl, None
    ifd, unit = ifl.split(".", 1)
    return ifd, unit


def is_included(ifl: str) -> bool:
    """
    Include-only: enforce only if the IFL or its parent IFD is in the include policy.
    """
    ifd, _unit = split_ifl(ifl)

    if ifl in INCLUDE_IFLS_EXACT or ifd in INCLUDE_IFDS_EXACT:
        return True

    for pat in INCLUDE_IFLS_REGEX:
        if pat.search(ifl):
            return True

    for pat in INCLUDE_IFDS_REGEX:
        if pat.search(ifd):
            return True

    return False


def mac_limit_for_ifl(ifl: str) -> int:
    if ifl in PER_IFL_LIMIT_EXACT:
        return int(PER_IFL_LIMIT_EXACT[ifl])

    for pat, limit in PER_IFL_LIMIT_REGEX:
        if pat.search(ifl):
            return int(limit)

    ifd, _unit = split_ifl(ifl)
    if ifd in PER_IFD_LIMIT_EXACT:
        return int(PER_IFD_LIMIT_EXACT[ifd])

    for pat, limit in PER_IFD_LIMIT_REGEX:
        if pat.search(ifd):
            return int(limit)

    return int(DEFAULT_MAC_LIMIT)


def extract_mac_entries_l2ng(j: dict) -> List[dict]:
    entries: List[dict] = []
    macdb = j.get("l2ng-l2ald-rtb-macdb", [])
    for db in macdb:
        vlan_blocks = db.get("l2ng-l2ald-mac-entry-vlan", [])
        for vb in vlan_blocks:
            mac_list = vb.get("l2ng-mac-entry", [])
            for mac_entry in mac_list:
                entries.append(mac_entry)
    return entries


def count_dynamic_macs_per_ifl(entries: List[dict]) -> Dict[str, int]:
    """
    Count only learned/dynamic MACs per IFL (port.unit).
    """
    counts: Dict[str, int] = {}
    for e in entries:
        mac = get_text_field(e, "l2ng-l2-mac-address")
        if not mac:
            continue

        flags = get_text_field(e, "l2ng-l2-mac-flags")
        if "D" not in [f.strip() for f in flags.split(",") if f.strip()]:
            continue

        ifl = get_text_field(e, "l2ng-l2-mac-logical-interface")
        if not ifl:
            continue

        ifd, unit = split_ifl(ifl)
        if ifd in IGNORE_IFDS:
            continue
        if not ENFORCE_IFD_REGEX.match(ifd):
            continue
        if unit is None:
            continue

        if not is_included(ifl):
            continue

        counts[ifl] = counts.get(ifl, 0) + 1

    return counts


def ifl_admin_is_up(ifl: str) -> bool:
    """
    Detect whether the logical interface is administratively enabled.
    Uses 'show interfaces terse <ifl>' and checks the Admin column.
    If we can't find the interface line, return False conservatively.
    """
    out = cli_text(f"show interfaces terse {ifl} | no-more", timeout=20)
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith(("Interface", "Physical", "Logical")):
            continue
        if line.startswith(ifl + " ") or line == ifl or line.startswith(ifl + "\t"):
            parts = line.split()
            if len(parts) >= 2:
                return parts[1].lower() == "up"
    return False


def scrub_state_for_reenabled_ifls(disabled_ifls: dict) -> dict:
    """
    If an IFL is recorded as disabled by the script, but is now admin-up,
    assume operator re-enabled it and remove the state entry so enforcement resumes.
    """
    to_delete = []
    for ifl in list(disabled_ifls.keys()):
        try:
            if ifl_admin_is_up(ifl):
                to_delete.append(ifl)
        except Exception as e:
            log(f"State check warning for {ifl}: {e}", "user.notice")

    for ifl in to_delete:
        log(f"{ifl} is admin-up again; removing from state so enforcement resumes", "user.notice")
        disabled_ifls.pop(ifl, None)

    return disabled_ifls


def build_commit_comment(ifls: List[str]) -> str:
    comment_targets = ", ".join(ifls[:5])
    if len(ifls) > 5:
        comment_targets += f", +{len(ifls) - 5} more"
    return f'{COMMIT_COMMENT} ({comment_targets})'


def disable_logical_interfaces_batch(ifls: List[str]) -> None:
    """
    Disable multiple logical interfaces in a single commit.
    """
    if not ifls:
        return

    set_cmds = []
    for ifl in ifls:
        ifd, unit = split_ifl(ifl)
        if unit is None:
            raise RuntimeError(f"Refusing to disable without unit: {ifl}")
        set_cmds.append(f"set interfaces {ifd} unit {unit} disable")

    cmd_parts = ["configure"]
    cmd_parts.extend(set_cmds)
    cmd_parts.append(f'commit comment "{build_commit_comment(ifls)}"')
    cmd_parts.append("exit")
    cmd = "; ".join(cmd_parts)

    rc, _out, err = run_cmd(["cli", "-c", cmd], timeout=120)
    if rc != 0:
        raise RuntimeError(f"Failed batch disable commit: rc={rc} err={err.strip()}")

    log(
        f"Disabled {len(ifls)} logical interface(s) in a single commit: {', '.join(ifls)}",
        "user.warning",
    )


def disable_single_logical_interface(ifl: str) -> None:
    """
    Disable one logical interface in its own commit.
    Used only as a fallback if the batch commit fails.
    """
    ifd, unit = split_ifl(ifl)
    if unit is None:
        raise RuntimeError(f"Refusing to disable without unit: {ifl}")

    cmd = (
        f"configure; "
        f"set interfaces {ifd} unit {unit} disable; "
        f'commit comment "{COMMIT_COMMENT} ({ifl})"; '
        f"exit"
    )
    rc, _out, err = run_cmd(["cli", "-c", cmd], timeout=90)
    if rc != 0:
        raise RuntimeError(f"Failed individual disable commit for {ifl}: rc={rc} err={err.strip()}")


def disable_with_batch_then_fallback(
    pending_ifls: List[str],
    pending_meta: Dict[str, Dict[str, int]],
) -> Dict[str, Dict[str, int]]:
    """
    First try one batch commit.
    If that fails, log the failure and try each interface individually.
    Returns only the interfaces that were successfully disabled and should be written to state.
    """
    successful_meta: Dict[str, Dict[str, int]] = {}

    if not pending_ifls:
        return successful_meta

    try:
        disable_logical_interfaces_batch(pending_ifls)
        successful_meta.update(pending_meta)
        return successful_meta
    except Exception as e:
        log(
            f"Batch disable commit failed for {len(pending_ifls)} interface(s): {', '.join(pending_ifls)} ; error: {e}",
            "user.err",
        )

    for ifl in pending_ifls:
        try:
            disable_single_logical_interface(ifl)
            successful_meta[ifl] = pending_meta[ifl]
            log(f"Fallback individual disable succeeded for {ifl}", "user.warning")
        except Exception as e:
            log(f"Fallback individual disable failed for {ifl}: {e}", "user.err")

    return successful_meta


def includes_configured() -> bool:
    return bool(INCLUDE_IFLS_EXACT or INCLUDE_IFLS_REGEX or INCLUDE_IFDS_EXACT or INCLUDE_IFDS_REGEX)


def enforce_once(iteration_num: int, scheduled_start: float) -> None:
    """
    Run one enforcement pass. Protected by the internal function lock.
    """
    actual_start = time.time()
    drift = actual_start - scheduled_start
    if drift > 0.5:
        log(
            f"Iteration {iteration_num}: starting {drift:.1f}s later than scheduled due to previous run still executing",
            "user.notice",
        )

    state = load_state()
    disabled_ifls = state.get("disabled_ifls", {})

    # If operator re-enabled something, remove it from state
    disabled_ifls = scrub_state_for_reenabled_ifls(disabled_ifls)
    state["disabled_ifls"] = disabled_ifls

    j = cli_json("show ethernet-switching table")
    entries = extract_mac_entries_l2ng(j)
    counts = count_dynamic_macs_per_ifl(entries)

    offenders: List[Tuple[str, int, int]] = []
    for ifl, c in counts.items():
        limit = mac_limit_for_ifl(ifl)
        if c > limit:
            offenders.append((ifl, c, limit))
    offenders.sort(key=lambda x: x[1], reverse=True)

    if offenders:
        pending_ifls: List[str] = []
        pending_meta: Dict[str, Dict[str, int]] = {}

        now_epoch = int(time.time())
        for ifl, c, limit in offenders:
            if ifl in disabled_ifls:
                continue

            log(
                f"MAC limit exceeded on {ifl}: learned {c} MACs (limit {limit}). Queuing logical interface for batch disable.",
                "user.warning",
            )
            pending_ifls.append(ifl)
            pending_meta[ifl] = {
                "disabled_epoch": now_epoch,
                "mac_count_at_disable": c,
                "limit": limit,
            }

        if pending_ifls:
            successful_meta = disable_with_batch_then_fallback(pending_ifls, pending_meta)
            disabled_ifls.update(successful_meta)

    state["disabled_ifls"] = disabled_ifls
    state["last_run_epoch"] = int(time.time())
    save_state(state)


def scheduler_loop() -> int:
    if RUN_COUNT < 1:
        log(f"Invalid RUN_COUNT={RUN_COUNT}; must be >= 1", "user.err")
        return 1
    if RUN_INTERVAL_SECONDS < 1:
        log(f"Invalid RUN_INTERVAL_SECONDS={RUN_INTERVAL_SECONDS}; must be >= 1", "user.err")
        return 1
    if not includes_configured():
        log("No INCLUDE_* policy configured; nothing to enforce", "user.notice")
        return 0

    initial_start = time.time()
    log(
        f"Starting scheduler loop: run_count={RUN_COUNT}, interval={RUN_INTERVAL_SECONDS}s",
        "user.notice",
    )

    for i in range(RUN_COUNT):
        scheduled_start = initial_start + (i * RUN_INTERVAL_SECONDS)

        now = time.time()
        sleep_for = scheduled_start - now
        if sleep_for > 0:
            time.sleep(sleep_for)

        lock_wait_logged = False
        wait_start = time.time()

        while not acquire_function_lock():
            if not lock_wait_logged:
                log(
                    f"Iteration {i + 1}: scheduled start reached but previous enforcement pass is still running; postponing until lock clears",
                    "user.notice",
                )
                lock_wait_logged = True
            time.sleep(0.5)

        try:
            if lock_wait_logged:
                waited = time.time() - wait_start
                log(
                    f"Iteration {i + 1}: enforcement lock cleared after waiting {waited:.1f}s; starting deferred run",
                    "user.notice",
                )

            enforce_once(i + 1, scheduled_start)
        finally:
            release_function_lock()

    log("Scheduler loop completed", "user.notice")
    return 0


def main() -> int:
    acquire_script_lock()
    try:
        return scheduler_loop()
    finally:
        release_lock(LOCK_FILE)
        release_function_lock()


if __name__ == "__main__":
    sys.exit(main())