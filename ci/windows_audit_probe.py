"""Bounded full-SACL observer; writes use a restricted medium thread token.

Uses public Win32 APIs only. Fixtures stay in one owned TemporaryDirectory.
No account, system audit policy, repository Rust source or external file changes.
ReplaceFile and TxF outcomes are reported independently; no universal TxF claim.
"""

import argparse
import ctypes as c
from ctypes import wintypes as w
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time

import windows_audit_api as win

api, check, k, a = win.api, win.check, win.k, win.a


class SID_ATTR(c.Structure):
    _fields_ = [("sid", c.c_void_p), ("attributes", w.DWORD)]






sid_from_text = api(a, "ConvertStringSidToSidW", [w.LPCWSTR, c.POINTER(c.c_void_p)], w.BOOL)
restricted = api(a, "CreateRestrictedToken", [w.HANDLE, w.DWORD, w.DWORD, c.c_void_p,
                  w.DWORD, c.c_void_p, w.DWORD, c.c_void_p, c.POINTER(w.HANDLE)], w.BOOL)
set_token = api(a, "SetTokenInformation", [w.HANDLE, w.DWORD, c.c_void_p, w.DWORD], w.BOOL)
sid_size = api(a, "GetLengthSid", [c.c_void_p], w.DWORD)
member = api(a, "CheckTokenMembership", [w.HANDLE, c.c_void_p, c.POINTER(w.BOOL)], w.BOOL)
token_info = api(a, "GetTokenInformation", [w.HANDLE, w.DWORD, c.c_void_p, w.DWORD, c.POINTER(w.DWORD)], w.BOOL)
get_control = api(a, "GetSecurityDescriptorControl", [c.c_void_p, c.POINTER(w.WORD), c.POINTER(w.DWORD)], w.BOOL)
impersonate = api(a, "ImpersonateLoggedOnUser", [w.HANDLE], w.BOOL)
current_thread = api(k, "GetCurrentThread", [], w.HANDLE)
open_thread_token = api(a, "OpenThreadToken", [w.HANDLE, w.DWORD, w.BOOL, c.POINTER(w.HANDLE)], w.BOOL)
initialize_acl = api(a, "InitializeAcl", [c.c_void_p, w.DWORD, w.DWORD], w.BOOL)
sid_to_text = api(a, "ConvertSidToStringSidW", [c.c_void_p, c.POINTER(c.c_void_p)], w.BOOL)
get_dacl = api(a, "GetSecurityDescriptorDacl", [c.c_void_p, c.POINTER(w.BOOL), c.POINTER(c.c_void_p), c.POINTER(w.BOOL)], w.BOOL)






def token_buffer(token, kind):
    size = w.DWORD()
    token_info(token, kind, None, 0, c.byref(size))
    data = c.create_string_buffer(size.value)
    check(token_info(token, kind, data, size, c.byref(size)))
    return data




def impersonate_restricted_writer():
    """Initialize Python normally, then restrict its file-operation thread.

    No reversion occurs before or during the writes. This validates effective
    API access, not initialization of a whole standard-user process.
    """
    win.privilege(4, False)
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
        check(impersonate(token))
    finally:
        if token: win.close(token)
        win.close(original)
        for sid in (admin, admin_account, medium):
            if sid: win.free(sid)


def ordinary_capabilities(path, thread_token=False):
    # Permanently remove Security privilege, in addition to max-privilege removal.
    # Thread mode already removed it before impersonation; never reopen the
    # high primary token for adjustment under the restricted effective token.
    if not thread_token: win.privilege(4, False)
    admin, is_member, token = c.c_void_p(), w.BOOL(), w.HANDLE()
    check(sid_from_text("S-1-5-32-544", c.byref(admin)))
    if thread_token:
        check(open_thread_token(current_thread(), 8, True, c.byref(token)))
    else:
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
                "only_change_notify_may_be_enabled": True, "sacl_access_denied": True,
                "token_scope": "effective impersonation thread" if thread_token else "primary process",
                "unrestricted_primary_process": thread_token}
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


def prepare_owned_fixture_root(path):
    """Make only this new synthetic root writable under ordinary effective rights.

    Hosted runner Temp can inherit admin-only/high-integrity policy. Explicitly
    grant this user and SYSTEM and set inheritable medium integrity before any
    case files exist; no external directory or system policy is changed.
    """
    token, text, sd = w.HANDLE(), c.c_void_p(), c.c_void_p()
    check(win.open_token(win.current(), 8, c.byref(token)))
    try:
        user = token_buffer(token, 1)
        check(sid_to_text(c.c_void_p.from_buffer(user).value, c.byref(text)))
        sddl = f"D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;{c.wstring_at(text)})S:(ML;OICI;NW;;;ME)"
        check(win.convert_in(sddl, 1, c.byref(sd), None))
        present, defaulted, dacl, sacl = w.BOOL(), w.BOOL(), c.c_void_p(), c.c_void_p()
        check(get_dacl(sd, c.byref(present), c.byref(dacl), c.byref(defaulted)))
        check(win.get_sacl(sd, c.byref(present), c.byref(sacl), c.byref(defaulted)))
        code = win.set_security(str(path), 1, 4 | 0x80000000 | 0x10, None, None, dacl, sacl)
        if code: raise c.WinError(code)
    finally:
        win.close(token)
        if text: win.free(text)
        if sd: win.free(sd)


def writer(path, action, result, thread_token=False):
    if thread_token: impersonate_restricted_writer()
    evidence = {"capabilities": ordinary_capabilities(path, thread_token)}
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
    if policy == "null":
        assert before["present"] and before["null"], before
    if policy.startswith("explicit"):
        assert "AU;" in before["sddl"], before
        assert bool(before["sacl_control"] & 0x2000) == (policy == "explicit-protected"), before
    if policy == "inherited":
        assert "ID" in before["sddl"], before
    row = {"policy": policy, "action": action, "before": before,
           "scope": "restricted effective thread; primary process initialized unrestricted",
           "empty_request_normalized_to_null": policy == "empty" and before["null"]}
    process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()),
                                "--writer-thread", str(path), action, str(result)],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               text=True, creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        if action == "kill":
            deadline = time.monotonic() + 15
            while not result.with_suffix(".ready").exists() and time.monotonic() < deadline:
                if process.poll() is not None: break
                time.sleep(.1)
            if not result.with_suffix(".ready").exists():
                raise RuntimeError("restricted writer did not reach TxF staging in15s")
            process.kill()
        output, _ = process.communicate(timeout=20)
        row["writer_exit"] = process.returncode
        row["writer_log"] = output
        if result.exists(): row["writer"] = json.loads(result.read_text())
        if action != "kill" and process.returncode != 0:
            raise RuntimeError(f"restricted thread writer failed with exit{process.returncode}: {output}")
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)
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
              "writer_scope": "restricted medium effective THREAD token; primary interpreter started unrestricted",
              "standard_user_process_launch": "not established; hosted primary-token launch failed0xC0000142",
              "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "cases": []}
    try:
        win.privilege(2, True)
        with tempfile.TemporaryDirectory(prefix="effectcraft-audit-") as temp:
            prepare_owned_fixture_root(Path(temp))
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
    if len(sys.argv) > 1 and sys.argv[1] in ("--writer", "--writer-thread"):
        try:
            writer(Path(sys.argv[2]), sys.argv[3], Path(sys.argv[4]), sys.argv[1] == "--writer-thread")
        except Exception as error:
            result = Path(sys.argv[4])
            evidence = json.loads(result.read_text()) if result.exists() else {}
            evidence["error"] = repr(error)
            result.write_text(json.dumps(evidence), encoding="utf-8")
            raise
    else:
        sys.exit(main())
