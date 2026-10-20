"""Bounded test-only full-SACL observer; writer has a restricted medium token.

Uses public Win32 APIs only. Fixtures stay in one owned TemporaryDirectory.
No account, system audit policy, repository Rust source or external file changes.
ReplaceFile and TxF outcomes are reported independently; no universal TxF claim.
"""

import argparse
import atexit
import ctypes as c
from ctypes import wintypes as w
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

import windows_audit_api as win

api, check, k, a = win.api, win.check, win.k, win.a


class SID_ATTR(c.Structure):
    _fields_ = [("sid", c.c_void_p), ("attributes", w.DWORD)]


class STARTUP(c.Structure):
    _fields_ = [("cb", w.DWORD), ("reserved", w.LPWSTR), ("desktop", w.LPWSTR),
                ("title", w.LPWSTR), ("x", w.DWORD), ("y", w.DWORD),
                ("width", w.DWORD), ("height", w.DWORD), ("chars_x", w.DWORD),
                ("chars_y", w.DWORD), ("fill", w.DWORD), ("flags", w.DWORD),
                ("show", w.WORD), ("reserved_size", w.WORD), ("reserved2", c.c_void_p),
                ("stdin", w.HANDLE), ("stdout", w.HANDLE), ("stderr", w.HANDLE)]


class PROCESS(c.Structure):
    _fields_ = [("process", w.HANDLE), ("thread", w.HANDLE), ("pid", w.DWORD), ("tid", w.DWORD)]


sid_from_text = api(a, "ConvertStringSidToSidW", [w.LPCWSTR, c.POINTER(c.c_void_p)], w.BOOL)
restricted = api(a, "CreateRestrictedToken", [w.HANDLE, w.DWORD, w.DWORD, c.c_void_p,
                  w.DWORD, c.c_void_p, w.DWORD, c.c_void_p, c.POINTER(w.HANDLE)], w.BOOL)
set_token = api(a, "SetTokenInformation", [w.HANDLE, w.DWORD, c.c_void_p, w.DWORD], w.BOOL)
sid_size = api(a, "GetLengthSid", [c.c_void_p], w.DWORD)
create_process = api(a, "CreateProcessAsUserW", [w.HANDLE, w.LPCWSTR, w.LPWSTR,
                     c.c_void_p, c.c_void_p, w.BOOL, w.DWORD, c.c_void_p, w.LPCWSTR,
                     c.POINTER(STARTUP), c.POINTER(PROCESS)], w.BOOL)
wait = api(k, "WaitForSingleObject", [w.HANDLE, w.DWORD], w.DWORD)
terminate = api(k, "TerminateProcess", [w.HANDLE, w.DWORD], w.BOOL)
exit_code = api(k, "GetExitCodeProcess", [w.HANDLE, c.POINTER(w.DWORD)], w.BOOL)
member = api(a, "CheckTokenMembership", [w.HANDLE, c.c_void_p, c.POINTER(w.BOOL)], w.BOOL)
token_info = api(a, "GetTokenInformation", [w.HANDLE, w.DWORD, c.c_void_p, w.DWORD, c.POINTER(w.DWORD)], w.BOOL)
get_control = api(a, "GetSecurityDescriptorControl", [c.c_void_p, c.POINTER(w.WORD), c.POINTER(w.DWORD)], w.BOOL)
initialize_acl = api(a, "InitializeAcl", [c.c_void_p, w.DWORD, w.DWORD], w.BOOL)
sid_to_text = api(a, "ConvertSidToStringSidW", [c.c_void_p, c.POINTER(c.c_void_p)], w.BOOL)
u = c.WinDLL("user32", use_last_error=True)
get_station = api(u, "GetProcessWindowStation", [], w.HANDLE)
set_station = api(u, "SetProcessWindowStation", [w.HANDLE], w.BOOL)
new_station = api(u, "CreateWindowStationW", [w.LPCWSTR, w.DWORD, w.DWORD, c.c_void_p], w.HANDLE)
new_desktop = api(u, "CreateDesktopW", [w.LPCWSTR, w.LPCWSTR, c.c_void_p, w.DWORD, w.DWORD, c.c_void_p], w.HANDLE)
close_station = api(u, "CloseWindowStation", [w.HANDLE], w.BOOL)
close_desktop = api(u, "CloseDesktop", [w.HANDLE], w.BOOL)
_private_desktop = None


class SECURITY_ATTRIBUTES(c.Structure):
    _fields_ = [("length", w.DWORD), ("descriptor", c.c_void_p), ("inherit", w.BOOL)]


def writer_desktop():
    """Avoid inheriting a service desktop whose DACL denies the restricted token.

    Create an owned, noninteractive station/desktop, granting only this user SID
    and SYSTEM. Never switch the visible desktop or modify its access policy.
    """
    global _private_desktop
    if _private_desktop:
        return _private_desktop[0]
    token, text, descriptor = w.HANDLE(), c.c_void_p(), c.c_void_p()
    check(win.open_token(win.current(), 8, c.byref(token)))
    try:
        user = token_buffer(token, 1)
        sid = c.c_void_p.from_buffer(user).value
        check(sid_to_text(sid, c.byref(text)))
        sddl = f"D:(A;;GA;;;SY)(A;;GA;;;{c.wstring_at(text)})S:(ML;;NW;;;ME)"
        check(win.convert_in(sddl, 1, c.byref(descriptor), None))
        attributes = SECURITY_ATTRIBUTES(c.sizeof(SECURITY_ATTRIBUTES), descriptor, False)
        name = f"EffectCraftAudit-{os.getpid()}"
        original = get_station()
        station = new_station(name, 1, 0xF037F, c.byref(attributes))
        check(station)
        desktop = None
        try:
            check(set_station(station))
            desktop = new_desktop("Writer", None, None, 0, 0x10000000, c.byref(attributes))
            check(desktop)
        finally:
            check(set_station(original))
            if not desktop: close_station(station)
        _private_desktop = (name + "\\Writer", station, desktop)
        atexit.register(lambda: (close_desktop(desktop), close_station(station)))
        return _private_desktop[0]
    finally:
        win.close(token)
        if text: win.free(text)
        if descriptor: win.free(descriptor)


def token_buffer(token, kind):
    size = w.DWORD()
    token_info(token, kind, None, 0, c.byref(size))
    data = c.create_string_buffer(size.value)
    check(token_info(token, kind, data, size, c.byref(size)))
    return data


def launch_restricted(path, action, result):
    original, token = w.HANDLE(), w.HANDLE()
    admin, admin_account, medium = c.c_void_p(), c.c_void_p(), c.c_void_p()
    check(win.open_token(win.current(), 0xF01FF, c.byref(original)))
    try:
        check(sid_from_text("S-1-5-32-544", c.byref(admin)))
        check(sid_from_text("S-1-5-114", c.byref(admin_account)))
        disabled = (SID_ATTR * 2)(SID_ATTR(admin, 0), SID_ATTR(admin_account, 0))
        check(restricted(original, 1, 2, disabled, 0, None, 0, None, c.byref(token)))
        check(sid_from_text("S-1-16-8192", c.byref(medium)))
        label = SID_ATTR(medium, 0x20)
        check(set_token(token, 25, c.byref(label), c.sizeof(label) + sid_size(medium)))
        command = c.create_unicode_buffer(subprocess.list2cmdline([
            sys.executable, str(Path(__file__).resolve()), "--writer", str(path), action, str(result)]))
        startup, process = STARTUP(), PROCESS()
        startup.cb = c.sizeof(startup)
        startup.desktop = writer_desktop()
        check(create_process(token, sys.executable, command, None, None, False,
                             0x08000000, None, str(path.parent), c.byref(startup), c.byref(process)))
        check(win.close(process.thread))
        return process.process
    finally:
        if token: win.close(token)
        win.close(original)
        if admin: win.free(admin)
        if admin_account: win.free(admin_account)
        if medium: win.free(medium)


def ordinary_capabilities(path):
    # Permanently remove Security privilege, in addition to max-privilege removal.
    win.privilege(4, False)
    admin, is_member, token = c.c_void_p(), w.BOOL(), w.HANDLE()
    check(sid_from_text("S-1-5-32-544", c.byref(admin)))
    check(win.open_token(win.current(), 8, c.byref(token)))
    try:
        check(member(None, admin, c.byref(is_member)))
        label = token_buffer(token, 25)
        sid = SID_ATTR.from_buffer(label).sid
        # SID revision/count then six-byte authority, followed by DWORD RIDs.
        count = c.string_at(sid, 2)[1]
        rid = int.from_bytes(c.string_at(sid + 8 + 4 * (count - 1), 4), "little")
        privileges = token_buffer(token, 3)
        number = w.DWORD.from_buffer(privileges).value
        offset = win.ONE_PRIVILEGE.luid.offset
        enabled = []
        change_notify = win.LUID()
        check(win.lookup(None, "SeChangeNotifyPrivilege", c.byref(change_notify)))
        for i in range(number):
            entry = win.ONE_PRIVILEGE.from_buffer_copy(
                b"\x01\x00\x00\x00" + privileges.raw[offset + i * 12:offset + (i + 1) * 12])
            if entry.attributes & 2:
                enabled.append((entry.luid.LowPart, entry.luid.HighPart))
        assert not is_member.value, "writer still has enabled Administrators SID"
        assert rid <= 8192, f"writer integrity is above medium: {rid}"
        assert all(value == (change_notify.LowPart, change_notify.HighPart) for value in enabled), enabled
        try:
            win.audit(path)
        except OSError as error:
            assert error.winerror in (5, 1314), error
        else:
            raise AssertionError("writer can inspect full SACL")
        return {"administrator_enabled": False, "integrity_rid": rid,
                "only_change_notify_may_be_enabled": True, "sacl_access_denied": True}
    finally:
        win.free(admin)
        win.close(token)


def audit_snapshot(path):
    sd = c.c_void_p()
    code = win.get_security(str(path), 1, 8, None, None, None, None, c.byref(sd))
    if code: raise c.WinError(code)
    try:
        present, defaulted, acl = w.BOOL(), w.BOOL(), c.c_void_p()
        control, revision = w.WORD(), w.DWORD()
        check(win.get_sacl(sd, c.byref(present), c.byref(acl), c.byref(defaulted)))
        check(get_control(sd, c.byref(control), c.byref(revision)))
        raw = b""
        if acl:
            # ACL header's AclSize (USHORT at offset2) bounds the descriptor-owned ACL.
            size = int.from_bytes(c.string_at(acl.value + 2, 2), "little")
            assert 8 <= size <= 65535
            raw = c.string_at(acl, size)
        return {"sddl": win.audit(path), "present": bool(present.value),
                "null": bool(present.value and not acl.value), "defaulted": bool(defaulted.value),
                "sacl_control": control.value & 0x2A30, "acl_hex": raw.hex()}
    finally:
        win.free(sd)


def set_audit(path, sddl, protected):
    sd = c.c_void_p()
    check(win.convert_in(sddl, 1, c.byref(sd), None))
    try:
        present, defaulted, acl = w.BOOL(), w.BOOL(), c.c_void_p()
        check(win.get_sacl(sd, c.byref(present), c.byref(acl), c.byref(defaulted)))
        code = win.set_security(str(path), 1, 8 | (0x40000000 if protected else 0x10000000),
                                None, None, None, acl)
        if code: raise c.WinError(code)
    finally:
        win.free(sd)


def writer(path, action, result):
    evidence = {"capabilities": ordinary_capabilities(path)}
    result.write_text(json.dumps(evidence), encoding="utf-8")
    if action == "replace":
        replacement = path.with_name("replacement.mov")
        replacement.write_bytes(b"new complete movie")
        check(win.replace(str(path), str(replacement), None, 0, None, None))
    else:
        tx = win.stage(path, b"new complete movie")
        if action == "kill":
            result.with_suffix(".ready").write_text("READY")
            time.sleep(60)
            raise AssertionError("observer must terminate writer")
        check((win.commit if action == "commit" else win.rollback)(tx))
        check(win.close(tx))
    evidence["completed"] = True
    result.write_text(json.dumps(evidence), encoding="utf-8")


def run_case(root, policy, action):
    directory = root / f"{policy}-{action}"
    directory.mkdir()
    path, result = directory / "movie.mov", directory / "writer.json"
    if policy == "inherited":
        set_audit(directory, "S:(AU;OICISAFA;FW;;;WD)", False)
    path.write_bytes(b"old complete movie")
    if policy.startswith("explicit"):
        win.seed(path, policy.endswith("protected" ) and not policy.endswith("unprotected"))
    elif policy == "empty":
        # SDDL 'S:' parsed successfully but produced a null ACL on the runner.
        # An actual zero-ACE ACL requires an initialized 8-byte ACL header.
        acl = c.create_string_buffer(8)
        check(initialize_acl(acl, 8, 2))
        code = win.set_security(str(path), 1, 8 | 0x40000000, None, None, None, acl)
        if code: raise c.WinError(code)
    elif policy == "null":
        set_audit(path, "S:NO_ACCESS_CONTROL", True)
    # 'default' captures the actual freshly-created absent/null state, without
    # pretending the filesystem can represent every requested distinction.
    before, identity = audit_snapshot(path), path.stat().st_ino
    (directory / "before.json").write_text(json.dumps(before), encoding="utf-8")
    if policy == "empty":
        assert before["present"] and not before["null"] and bytes.fromhex(before["acl_hex"])[4:6] == b"\0\0", before
    if policy == "null":
        assert before["present"] and before["null"], before
    if policy.startswith("explicit"):
        assert "AU;" in before["sddl"], before
        assert bool(before["sacl_control"] & 0x2000) == (policy == "explicit-protected"), before
    if policy == "inherited":
        assert "ID" in before["sddl"], before
    row = {"policy": policy, "action": action, "before": before}
    process = launch_restricted(path, action, result)
    try:
        if action == "kill":
            deadline = time.monotonic() + 15
            while not result.with_suffix(".ready").exists() and time.monotonic() < deadline:
                if wait(process, 100) == 0: break
            if not result.with_suffix(".ready").exists():
                raise RuntimeError("restricted writer did not reach TxF staging in15s")
            check(terminate(process, 75))
        if wait(process, 20000) != 0:
            check(terminate(process, 76))
            raise RuntimeError("restricted writer exceeded20s")
        code = w.DWORD()
        check(exit_code(process, c.byref(code)))
        row["writer_exit"] = code.value
        if result.exists(): row["writer"] = json.loads(result.read_text())
        if action != "kill" and code.value != 0:
            raise RuntimeError(f"restricted writer failed with exit{code.value}")
    finally:
        if wait(process, 0) != 0:
            terminate(process, 77)
            wait(process, 5000)
        win.close(process)
    row["after"] = audit_snapshot(path)
    row["same_identity"] = identity == path.stat().st_ino
    row["audit_exact_match"] = row["before"] == row["after"]
    expected = b"new complete movie" if action in ("replace", "commit") else b"old complete movie"
    row["bytes_match"] = path.read_bytes() == expected
    row["pass"] = row["audit_exact_match"] and row["bytes_match"] and (action == "replace" or row["same_identity"])
    return row


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    report = {"kind": "fixture-experiment-not-product-validation", "python": sys.version,
              "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "cases": []}
    try:
        win.privilege(2, True)
        with tempfile.TemporaryDirectory(prefix="effectcraft-audit-") as temp:
            for policy in ("explicit-unprotected", "explicit-protected", "empty", "null", "default", "inherited"):
                for action in ("replace", "commit", "rollback", "kill"):
                    try:
                        row = run_case(Path(temp), policy, action)
                    except Exception as error:
                        row = {"policy": policy, "action": action, "pass": False,
                               "error_kind": "fixture-or-writer-execution", "error": repr(error)}
                        directory = Path(temp) / f"{policy}-{action}"
                        for name, key in (("before.json", "before"), ("writer.json", "writer")):
                            if (directory / name).exists():
                                row[key] = json.loads((directory / name).read_text())
                        if (directory / "movie.mov").exists():
                            try: row["after"] = audit_snapshot(directory / "movie.mov")
                            except Exception as observer_error: row["after_error"] = repr(observer_error)
                    report["cases"].append(row)
                    print(json.dumps(row), flush=True)
    except Exception as error:
        report["blocked"] = repr(error)
        print("OBSERVER BLOCKED:", repr(error), flush=True)
    report["replacefile_all_pass"] = len(report["cases"]) == 24 and all(r["pass"] for r in report["cases"] if r["action"] == "replace")
    report["txf_all_pass"] = len(report["cases"]) == 24 and all(r["pass"] for r in report["cases"] if r["action"] != "replace")
    (args.output / "audit-results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return 0 if report["replacefile_all_pass"] and report["txf_all_pass"] else 1


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--writer":
        try:
            writer(Path(sys.argv[2]), sys.argv[3], Path(sys.argv[4]))
        except Exception as error:
            result = Path(sys.argv[4])
            evidence = json.loads(result.read_text()) if result.exists() else {}
            evidence["error"] = repr(error)
            result.write_text(json.dumps(evidence), encoding="utf-8")
            raise
    else:
        sys.exit(main())
