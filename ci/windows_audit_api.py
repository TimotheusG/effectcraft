# Probe helper adapted from export-owner fixture; no product runtime dependency.
# Probe only: official Win32 TxF APIs. No repository source or external files modified.
import ctypes as c
from ctypes import wintypes as w
from pathlib import Path
import tempfile, subprocess, sys, time, os
k = c.WinDLL('kernel32', use_last_error=True)
t = c.WinDLL('ktmw32', use_last_error=True)
def api(dll, name, args, result):
    f = getattr(dll, name); f.argtypes=args; f.restype=result; return f
transaction = api(t, 'CreateTransaction', [c.c_void_p,c.c_void_p,w.DWORD,w.DWORD,w.DWORD,w.DWORD,w.LPWSTR], w.HANDLE)
open_tx = api(k, 'CreateFileTransactedW', [w.LPCWSTR,w.DWORD,w.DWORD,c.c_void_p,w.DWORD,w.DWORD,w.HANDLE,w.HANDLE,c.c_void_p,c.c_void_p],w.HANDLE)
write = api(k,'WriteFile',[w.HANDLE,c.c_void_p,w.DWORD,c.POINTER(w.DWORD),c.c_void_p],w.BOOL)
end = api(k,'SetEndOfFile',[w.HANDLE],w.BOOL)
close = api(k,'CloseHandle',[w.HANDLE],w.BOOL)
commit = api(t,'CommitTransaction',[w.HANDLE],w.BOOL)
rollback = api(t,'RollbackTransaction',[w.HANDLE],w.BOOL)
def check(ok):
    if not ok: raise c.WinError(c.get_last_error())
def stage(path, data, tx=None):
    if tx is None: tx=transaction(None,None,0,0,0,0,None)
    if tx == c.c_void_p(-1).value: raise c.WinError(c.get_last_error())
    f = open_tx(str(path),0x40000000,7,None,3,0x80,None,tx,None,None)
    if f == c.c_void_p(-1).value:
        close(tx); raise c.WinError(c.get_last_error())
    n=w.DWORD()
    check(write(f,data,len(data),c.byref(n),None)); assert n.value==len(data)
    check(end(f)); check(close(f))
    return tx

# A privileged fixture observer and a separate exporter with audit privilege removed.
# Writes ONLY into its own TemporaryDirectory; no system audit policy is changed.
a=c.WinDLL('advapi32',use_last_error=True)
class LUID(c.Structure): _fields_=[('LowPart',w.DWORD),('HighPart',w.LONG)]
class ONE_PRIVILEGE(c.Structure): _fields_=[('count',w.DWORD),('luid',LUID),('attributes',w.DWORD)]
open_token=api(a,'OpenProcessToken',[w.HANDLE,w.DWORD,c.POINTER(w.HANDLE)],w.BOOL)
lookup=api(a,'LookupPrivilegeValueW',[w.LPCWSTR,w.LPCWSTR,c.POINTER(LUID)],w.BOOL)
adjust=api(a,'AdjustTokenPrivileges',[w.HANDLE,w.BOOL,c.c_void_p,w.DWORD,c.c_void_p,c.c_void_p],w.BOOL)
current=api(k,'GetCurrentProcess',[],w.HANDLE)
get_security=api(a,'GetNamedSecurityInfoW',[w.LPWSTR,w.DWORD,w.DWORD,c.c_void_p,c.c_void_p,c.c_void_p,c.c_void_p,c.POINTER(c.c_void_p)],w.DWORD)
set_security=api(a,'SetNamedSecurityInfoW',[w.LPWSTR,w.DWORD,w.DWORD,c.c_void_p,c.c_void_p,c.c_void_p,c.c_void_p],w.DWORD)
convert_in=api(a,'ConvertStringSecurityDescriptorToSecurityDescriptorW',[w.LPCWSTR,w.DWORD,c.POINTER(c.c_void_p),c.c_void_p],w.BOOL)
convert_out=api(a,'ConvertSecurityDescriptorToStringSecurityDescriptorW',[c.c_void_p,w.DWORD,w.DWORD,c.POINTER(c.c_void_p),c.c_void_p],w.BOOL)
get_sacl=api(a,'GetSecurityDescriptorSacl',[c.c_void_p,c.POINTER(w.BOOL),c.POINTER(c.c_void_p),c.POINTER(w.BOOL)],w.BOOL)
free=api(k,'LocalFree',[c.c_void_p],c.c_void_p)
replace=api(k,'ReplaceFileW',[w.LPCWSTR,w.LPCWSTR,w.LPCWSTR,w.DWORD,c.c_void_p,c.c_void_p],w.BOOL)
def privilege(attributes, required):
    token=w.HANDLE();check(open_token(current(),0x28,c.byref(token)))
    try:
        luid=LUID();check(lookup(None,'SeSecurityPrivilege',c.byref(luid)))
        item=ONE_PRIVILEGE(1,luid,attributes);c.set_last_error(0)
        check(adjust(token,False,c.byref(item),0,None,None))
        code=c.get_last_error()
        if required and code: raise c.WinError(code)
    finally: check(close(token))
def audit(path):
    sd=c.c_void_p();code=get_security(str(path),1,8,None,None,None,None,c.byref(sd))
    if code: raise c.WinError(code)
    try:
        text=c.c_void_p();check(convert_out(sd,1,8,c.byref(text),None))
        try: return c.wstring_at(text)
        finally: free(text)
    finally: free(sd)
def seed(path, protected):
    sd=c.c_void_p();check(convert_in('S:P(AU;SAFA;FW;;;WD)',1,c.byref(sd),None))
    try:
        present=w.BOOL();defaulted=w.BOOL();acl=c.c_void_p()
        check(get_sacl(sd,c.byref(present),c.byref(acl),c.byref(defaulted)))
        code=set_security(str(path),1,8|(0x40000000 if protected else 0x10000000),None,None,None,acl)
        if code: raise c.WinError(code)
    finally: free(sd)
