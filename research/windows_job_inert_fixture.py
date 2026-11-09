"""A26-style run-id handoff + owned Windows Job: INERT GitHub-runner proof.

NO Strata imports, model requests, Docker API, host inspection, or network.
Runs only when explicitly invoked on a GitHub-hosted Windows runner.
A PASS does not verify the existing A26 implementation or the user's PC.
"""
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import time

RUN_ID_RE = re.compile(r"\A[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}\Z")
KILL_ON_JOB_CLOSE = 0x2000


def digest(s):
    return hashlib.sha256(s.encode("ascii")).hexdigest()


def child():
    if os.environ.get("STRATA_INERT_ONLY") != "1":
        return 80
    if sys.stdin.readline(4) != "GO\n":
        return 81
    try:
        root = Path(os.environ["STRATA_FIXTURE_DIR"])
        rid = os.environ["STRATA_FIXTURE_RUN_ID"]
        token = os.environ["STRATA_FIXTURE_TOKEN"]
        mode = os.environ["STRATA_FIXTURE_MODE"]
        if not RUN_ID_RE.fullmatch(rid) or root.name != rid:
            return 82
        claim = json.loads((root / "claim.json").read_text(encoding="ascii"))
        if claim != {"run_id": rid, "token_sha256": digest(token)}:
            return 83
        (root / "entered").write_text("INERT_ONLY", encoding="ascii")
        if mode == "hang":
            subprocess.Popen(
                [sys.executable, "-I", str(Path(__file__).resolve()), "--grandchild"],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW,
                env={"STRATA_INERT_ONLY": "1"})
            time.sleep(25)
        elif mode != "normal":
            return 84
        return 0
    except (KeyError, ValueError, OSError, UnicodeError):
        return 85


class BasicLimit(ctypes.Structure):
    _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong),
                ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD)]


class IoCounters(ctypes.Structure):
    _fields_ = [(n, ctypes.c_ulonglong) for n in (
        "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
        "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]


class ExtendedLimit(ctypes.Structure):
    _fields_ = [("BasicLimitInformation", BasicLimit),
                ("IoInfo", IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t)]


class Accounting(ctypes.Structure):
    _fields_ = [("TotalUserTime", ctypes.c_longlong),
                ("TotalKernelTime", ctypes.c_longlong),
                ("ThisPeriodTotalUserTime", ctypes.c_longlong),
                ("ThisPeriodKernelTime", ctypes.c_longlong),
                ("TotalPageFaultCount", wintypes.DWORD),
                ("TotalProcesses", wintypes.DWORD),
                ("ActiveProcesses", wintypes.DWORD),
                ("TotalTerminatedProcesses", wintypes.DWORD)]


class OwnedJob:
    def __init__(self):
        self.k = ctypes.WinDLL("kernel32", use_last_error=True)
        k = self.k
        k.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
        k.CreateJobObjectW.restype = wintypes.HANDLE
        k.SetInformationJobObject.argtypes = [
            wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
        k.SetInformationJobObject.restype = wintypes.BOOL
        k.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        k.AssignProcessToJobObject.restype = wintypes.BOOL
        k.IsProcessInJob.argtypes = [
            wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
        k.IsProcessInJob.restype = wintypes.BOOL
        k.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        k.TerminateJobObject.restype = wintypes.BOOL
        k.QueryInformationJobObject.argtypes = [
            wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID,
            wintypes.DWORD, wintypes.LPVOID]
        k.QueryInformationJobObject.restype = wintypes.BOOL
        k.CloseHandle.argtypes = [wintypes.HANDLE]
        k.CloseHandle.restype = wintypes.BOOL
        self.handle = k.CreateJobObjectW(None, None)
        if not self.handle:
            raise RuntimeError("HOLD_CREATE_JOB_FAILED")
        limit = ExtendedLimit()
        limit.BasicLimitInformation.LimitFlags = KILL_ON_JOB_CLOSE
        if not k.SetInformationJobObject(
                self.handle, 9, ctypes.byref(limit), ctypes.sizeof(limit)):
            k.CloseHandle(self.handle)
            self.handle = None
            raise RuntimeError("HOLD_KILL_ON_CLOSE_FAILED")

    def assign_and_attest(self, proc):
        if not self.k.AssignProcessToJobObject(self.handle, int(proc._handle)):
            raise RuntimeError("HOLD_ASSIGN_FAILED")
        inside = wintypes.BOOL()
        if not self.k.IsProcessInJob(
                int(proc._handle), self.handle, ctypes.byref(inside)) or not inside.value:
            raise RuntimeError("HOLD_MEMBERSHIP_UNKNOWN")

    def active(self):
        info = Accounting()
        if not self.k.QueryInformationJobObject(
                self.handle, 1, ctypes.byref(info), ctypes.sizeof(info), None):
            raise RuntimeError("HOLD_JOB_ACCOUNTING_UNKNOWN")
        return int(info.ActiveProcesses)

    def terminate(self):
        if not self.k.TerminateJobObject(self.handle, 1):
            raise RuntimeError("HOLD_OWNED_TERMINATION_FAILED")

    def close(self):
        if self.handle:
            if not self.k.CloseHandle(self.handle):
                raise RuntimeError("HOLD_JOB_CLOSE_FAILED")
            self.handle = None


def require(ok, label):
    if not ok:
        raise RuntimeError(label)


def case(mode):
    """Every case uses its own fresh private run directory and Job."""
    with tempfile.TemporaryDirectory(prefix="strata-inert-") as tmp:
        rid = "20261109T000000Z-" + secrets.token_hex(4)
        root = Path(tmp) / rid
        root.mkdir()
        token = secrets.token_hex(16)
        claim_sha = digest(token + "bad") if mode == "tamper" else digest(token)
        # Atomic claim: separate reservation/claim is intentionally a fixture,
        # not a proof of A26's existing on-disk reservation implementation.
        with (root / "claim.json").open("x", encoding="ascii") as f:
            json.dump({"run_id": rid, "token_sha256": claim_sha}, f)
        env = {k: os.environ[k] for k in (
            "SystemRoot", "WINDIR", "PATH", "TEMP", "TMP") if k in os.environ}
        env.update(STRATA_INERT_ONLY="1", STRATA_FIXTURE_DIR=str(root),
                   STRATA_FIXTURE_RUN_ID=rid, STRATA_FIXTURE_TOKEN=token,
                   STRATA_FIXTURE_MODE="hang" if mode == "timeout" else "normal")
        job = None
        proc = None
        assigned = False
        try:
            job = OwnedJob()
            proc = subprocess.Popen(
                [sys.executable, "-I", str(Path(__file__).resolve()), "--child"],
                env=env, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
            job.assign_and_attest(proc)
            assigned = True
            require(proc.poll() is None, "HOLD_GATE_EXITED_EARLY")
            require(job.active() >= 1, "HOLD_NO_JOB_MEMBER")
            if mode == "no_go":
                proc.stdin.close()
                require(proc.wait(timeout=8) == 81, "HOLD_NO_GO_NOT_REJECTED")
                require(not (root / "entered").exists(), "HOLD_ENTERED_WITHOUT_GO")
            else:
                proc.stdin.write(b"GO\n")
                proc.stdin.flush()
                proc.stdin.close()
                if mode == "timeout":
                    deadline = time.monotonic() + 7
                    while time.monotonic() < deadline:
                        if (root / "entered").exists() and job.active() >= 2:
                            break
                        time.sleep(0.05)
                    else:
                        raise RuntimeError("HOLD_GRANDCHILD_NOT_OWNED")
                    job.terminate()
                    require(proc.wait(timeout=8) != 0, "HOLD_HUNG_GATE_SURVIVED")
                else:
                    status = proc.wait(timeout=8)
                    require(status == (83 if mode == "tamper" else 0),
                            "HOLD_GATE_EXIT_UNEXPECTED")
                require((root / "entered").exists() == (mode in ("normal", "timeout")),
                        "HOLD_RELEASE_BOUNDARY_INCORRECT")
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline and job.active() != 0:
                time.sleep(0.05)
            require(job.active() == 0, "HOLD_JOB_DESCENDANTS_REMAIN")
            return {"case": mode, "status": "INERT_PASS"}
        finally:
            if job:
                if assigned:
                    # Only this newly created Job is targeted. No PID search.
                    try:
                        if job.active() != 0:
                            job.terminate()
                    finally:
                        job.close()
                else:
                    # Gate was never released and is the exact Popen child.
                    try:
                        if proc is not None and proc.poll() is None:
                            proc.terminate()
                            proc.wait(timeout=8)
                    finally:
                        # Kill-on-close still applies if assignment partly succeeded.
                        job.close()


def main():
    if (os.name != "nt" or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_OS") != "Windows"
            or os.environ.get("STRATA_INERT_ONLY") != "1"):
        print("HOLD_UNAUTHORIZED_PLATFORM_OR_RUNNER")
        return 2
    results = []
    for name in ("no_go", "tamper", "normal", "timeout"):
        results.append(case(name))
    print(json.dumps({"schema": "strata-inert-windows-owner-v1",
                      "status": "RESEARCH_ONLY_PASS",
                      "model_requests": 0, "docker_runs": 0,
                      "actual_a26_integrated": False,
                      "windows_job_owner_cases": results}, sort_keys=True))
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--child":
        sys.exit(child())
    if len(sys.argv) == 2 and sys.argv[1] == "--grandchild":
        if os.environ.get("STRATA_INERT_ONLY") != "1":
            sys.exit(89)
        time.sleep(25)
        sys.exit(0)
    if len(sys.argv) != 1:
        sys.exit(90)
    try:
        sys.exit(main())
    except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
        # Fixed label only; do not print paths/PIDs/secret token.
        reason = str(exc)
        print(reason if reason.startswith("HOLD_") else "HOLD_INERT_UNCLASSIFIED")
        sys.exit(1)
