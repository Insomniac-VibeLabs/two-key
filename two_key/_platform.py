"""Owner-only files, locks, and no-follow opens on Linux, macOS, and Windows (0.6.0).

Two-Key keeps its keys in files only their owner can read, opens them without following a symlink,
and serialises ledger writes and token redemption with a cross-process lock. POSIX does this with mode
bits, ``O_NOFOLLOW``, and ``flock``. Windows has none of them: Python reports every file there as mode
0666, ``O_NOFOLLOW`` does not exist, and there is no ``fcntl``. This module does each the native way on
each platform, with the standard library only (``ctypes`` on Windows; no pywin32).

On POSIX every function here does exactly what the callers did before 0.6.0.

On Windows:

- A file Two-Key creates gets a protected access list (nothing inherited) that gives full control to the
  current user only, ``D:P(A;;FA;;;<user SID>)``, set in ``CreateFileW`` itself, so the file is never
  readable by anyone else, not even for an instant. A directory gets the same, inheritable.
- A key is accepted when its owner and every "allow" entry in its access list is the current user,
  SYSTEM, or the local Administrators group (maintainer's decision, 2026-10-15). SYSTEM and
  Administrators can read any file on the machine anyway, as root can on POSIX.
- A file is opened with ``FILE_FLAG_OPEN_REPARSE_POINT``, so a symlink or junction is opened as itself
  and refused, with no gap between the check and the open.
- The lock is ``LockFileEx`` on byte 0 of a separate lock file: exclusive and blocking, released when
  the handle closes or the process ends, like ``flock``. It is a mandatory lock, but only the lock file
  carries it, so it never blocks reading the ledger.
"""

from __future__ import annotations

import os
import stat
import time

WINDOWS = os.name == "nt"
# Windows translates newlines (and stops at Ctrl-Z) on a descriptor opened in text mode. Every
# descriptor Two-Key opens with os.open carries this; on POSIX it is 0.
O_BINARY = getattr(os, "O_BINARY", 0)
O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)

SYSTEM_SID = "S-1-5-18"
# OWNER RIGHTS: an entry for whoever owns the file, which is checked to be one of the trusted accounts.
OWNER_RIGHTS_SID = "S-1-3-4"
ADMINISTRATORS_SID = "S-1-5-32-544"
# The account that owns Windows' own files (Program Files, System32): trusted for write_problem only.
TRUSTED_INSTALLER_SID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
# Names for the accounts a write_problem message most often names.
_SID_NAMES = {"S-1-1-0": "Everyone", "S-1-5-11": "Authenticated Users", "S-1-5-32-545": "Users",
              "S-1-5-4": "INTERACTIVE"}

if WINDOWS:  # pragma: no cover - exercised on the Windows CI runner
    import ctypes
    import msvcrt
    from ctypes import wintypes

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _adv = ctypes.WinDLL("advapi32", use_last_error=True)

    _GENERIC_READ = 0x80000000
    _GENERIC_WRITE = 0x40000000
    _READ_CONTROL = 0x00020000
    _FILE_SHARE_ALL = 0x1 | 0x2 | 0x4
    _CREATE_NEW = 1
    _OPEN_EXISTING = 3
    _OPEN_ALWAYS = 4
    _FILE_ATTRIBUTE_NORMAL = 0x80
    _FILE_ATTRIBUTE_REPARSE_POINT = 0x400
    _FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    _INVALID_HANDLE = wintypes.HANDLE(-1).value
    _SE_FILE_OBJECT = 1
    _OWNER_SECURITY_INFORMATION = 0x1
    _DACL_SECURITY_INFORMATION = 0x4
    _PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
    _SDDL_REVISION_1 = 1
    _TOKEN_QUERY = 0x8
    _TOKEN_USER = 1
    _ACL_SIZE_INFORMATION = 2
    _ACCESS_ALLOWED_ACE_TYPE = 0
    _ACCESS_DENIED_ACE_TYPE = 1
    _INHERIT_ONLY_ACE = 0x08
    _LOCKFILE_EXCLUSIVE_LOCK = 0x2
    # Rights another account may hold without reaching the contents: wait on the handle, read the
    # access list, read the timestamps and size.
    _HARMLESS = 0x00100000 | _READ_CONTROL | 0x80
    _SHARING_VIOLATION = (5, 32, 33)    # access denied, sharing violation, lock violation

    class _SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p),
                    ("bInheritHandle", wintypes.BOOL)]

    class _ACE_HEADER(ctypes.Structure):
        _fields_ = [("AceType", ctypes.c_ubyte), ("AceFlags", ctypes.c_ubyte), ("AceSize", wintypes.WORD)]

    class _ACCESS_ALLOWED_ACE(ctypes.Structure):
        _fields_ = [("Header", _ACE_HEADER), ("Mask", wintypes.DWORD), ("SidStart", wintypes.DWORD)]

    class _ACL_SIZE_INFORMATION_T(ctypes.Structure):
        _fields_ = [("AceCount", wintypes.DWORD), ("AclBytesInUse", wintypes.DWORD),
                    ("AclBytesFree", wintypes.DWORD)]

    class _OVERLAPPED(ctypes.Structure):
        _fields_ = [("Internal", ctypes.c_void_p), ("InternalHigh", ctypes.c_void_p),
                    ("Offset", wintypes.DWORD), ("OffsetHigh", wintypes.DWORD), ("hEvent", wintypes.HANDLE)]

    _k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                 ctypes.POINTER(_SECURITY_ATTRIBUTES), wintypes.DWORD, wintypes.DWORD,
                                 wintypes.HANDLE]
    _k32.CreateFileW.restype = wintypes.HANDLE
    _k32.CloseHandle.argtypes = [wintypes.HANDLE]
    _k32.CloseHandle.restype = wintypes.BOOL
    _k32.LocalFree.argtypes = [ctypes.c_void_p]
    _k32.LocalFree.restype = ctypes.c_void_p
    _k32.GetCurrentProcess.argtypes = []
    _k32.GetCurrentProcess.restype = wintypes.HANDLE
    _k32.LockFileEx.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
                                wintypes.DWORD, ctypes.POINTER(_OVERLAPPED)]
    _k32.LockFileEx.restype = wintypes.BOOL
    _k32.UnlockFileEx.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
                                  ctypes.POINTER(_OVERLAPPED)]
    _k32.UnlockFileEx.restype = wintypes.BOOL
    _adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    _adv.OpenProcessToken.restype = wintypes.BOOL
    _adv.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                         ctypes.POINTER(wintypes.DWORD)]
    _adv.GetTokenInformation.restype = wintypes.BOOL
    _adv.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    _adv.ConvertSidToStringSidW.restype = wintypes.BOOL
    _adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.ULONG)]
    _adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    _adv.GetSecurityDescriptorDacl.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL),
                                               ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL)]
    _adv.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    _adv.SetNamedSecurityInfoW.argtypes = [wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p,
                                           ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    _adv.SetNamedSecurityInfoW.restype = wintypes.DWORD
    _adv.GetSecurityInfo.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD,
                                     ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
                                     ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
                                     ctypes.POINTER(ctypes.c_void_p)]
    _adv.GetSecurityInfo.restype = wintypes.DWORD
    _adv.GetAclInformation.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.c_int]
    _adv.GetAclInformation.restype = wintypes.BOOL
    _adv.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    _adv.GetAce.restype = wintypes.BOOL

    def _error(code: int, path=None) -> OSError:
        return OSError(None, ctypes.FormatError(code).strip(), None if path is None else os.fspath(path), code)

    def _last_error(path=None) -> OSError:
        return _error(ctypes.get_last_error(), path)

    def _sid_string(psid) -> str:
        out = wintypes.LPWSTR()
        if not _adv.ConvertSidToStringSidW(psid, ctypes.byref(out)):
            raise _last_error()
        try:
            return out.value
        finally:
            _k32.LocalFree(ctypes.cast(out, ctypes.c_void_p))

    _USER_SID = None

    def current_user_sid() -> str:
        """The string SID of the account this process runs as."""
        global _USER_SID
        if _USER_SID is None:
            token = wintypes.HANDLE()
            if not _adv.OpenProcessToken(_k32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)):
                raise _last_error()
            try:
                size = wintypes.DWORD()
                _adv.GetTokenInformation(token, _TOKEN_USER, None, 0, ctypes.byref(size))
                buf = ctypes.create_string_buffer(size.value)
                if not _adv.GetTokenInformation(token, _TOKEN_USER, buf, size, ctypes.byref(size)):
                    raise _last_error()
                _USER_SID = _sid_string(ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0])
            finally:
                _k32.CloseHandle(token)
        return _USER_SID

    class _Descriptor:
        """A self-relative security descriptor built from SDDL, freed on exit."""

        def __init__(self, sddl: str):
            self.ptr = ctypes.c_void_p()
            if not _adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl, _SDDL_REVISION_1, ctypes.byref(self.ptr), None):
                raise _last_error()

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            _k32.LocalFree(self.ptr)
            return False

        def dacl(self):
            present, defaulted, acl = wintypes.BOOL(), wintypes.BOOL(), ctypes.c_void_p()
            if not _adv.GetSecurityDescriptorDacl(self.ptr, ctypes.byref(present), ctypes.byref(acl),
                                                  ctypes.byref(defaulted)):
                raise _last_error()
            return acl

    def _to_fd(handle, flags: int, path) -> int:
        try:
            fd = msvcrt.open_osfhandle(handle, flags & (os.O_RDONLY | os.O_WRONLY | os.O_RDWR | os.O_APPEND))
        except BaseException:
            _k32.CloseHandle(handle)
            raise
        msvcrt.setmode(fd, os.O_BINARY)
        try:
            st = os.fstat(fd)
        except BaseException:
            os.close(fd)
            raise
        if st.st_file_attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            os.close(fd)
            raise OSError(None, "is a symbolic link, junction, or other reparse point", os.fspath(path), 1921)
        return fd

    def _create_file(path, flags: int, sddl: str | None) -> int:
        access = _READ_CONTROL
        if flags & os.O_RDWR:
            access |= _GENERIC_READ | _GENERIC_WRITE
        elif flags & os.O_WRONLY:
            access |= _GENERIC_WRITE
        else:
            access |= _GENERIC_READ
        if flags & os.O_CREAT and flags & os.O_EXCL:
            disposition = _CREATE_NEW
        elif flags & os.O_CREAT:
            disposition = _OPEN_ALWAYS
        else:
            disposition = _OPEN_EXISTING
        attrs = None
        descriptor = _Descriptor(sddl) if sddl else None
        try:
            if descriptor is not None:
                attrs = _SECURITY_ATTRIBUTES(ctypes.sizeof(_SECURITY_ATTRIBUTES), descriptor.ptr, False)
            handle = _k32.CreateFileW(os.fspath(path), access, _FILE_SHARE_ALL,
                                      ctypes.byref(attrs) if attrs is not None else None, disposition,
                                      _FILE_ATTRIBUTE_NORMAL | _FILE_FLAG_OPEN_REPARSE_POINT, None)
            if handle == _INVALID_HANDLE or handle is None:
                raise _last_error(path)
        finally:
            if descriptor is not None:
                descriptor.__exit__()
        return _to_fd(handle, flags, path)

    def _owner_only_sddl(directory: bool) -> str:
        inherit = "OICI" if directory else ""
        return f"D:P(A;{inherit};FA;;;{current_user_sid()})"

    def _access_problem_handle(handle, forbidden: int | None = None, *, owner: bool = False,
                               also_trusted: tuple = (), granted: str | None = None) -> str | None:
        owner_psid, dacl, descriptor = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
        rc = _adv.GetSecurityInfo(handle, _SE_FILE_OBJECT,
                                  _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
                                  ctypes.byref(owner_psid), None, ctypes.byref(dacl), None,
                                  ctypes.byref(descriptor))
        if rc:
            return f"its access list cannot be read ({ctypes.FormatError(rc).strip()})"
        try:
            trusted = {current_user_sid(), SYSTEM_SID, ADMINISTRATORS_SID, *also_trusted}
            owner_sid = _sid_string(owner_psid)
            if owner_sid not in trusted and (forbidden is None or owner):
                return f"it is owned by {owner_sid}, not by you"
            if owner_sid in trusted:
                trusted.add(OWNER_RIGHTS_SID)
            if not dacl.value:
                return "it has no access list, so everyone has full access"
            info = _ACL_SIZE_INFORMATION_T()
            if not _adv.GetAclInformation(dacl, ctypes.byref(info), ctypes.sizeof(info), _ACL_SIZE_INFORMATION):
                return "its access list cannot be read"
            for index in range(info.AceCount):
                ace = ctypes.c_void_p()
                if not _adv.GetAce(dacl, index, ctypes.byref(ace)):
                    return "its access list cannot be read"
                header = _ACE_HEADER.from_address(ace.value)
                if header.AceFlags & _INHERIT_ONLY_ACE or header.AceType == _ACCESS_DENIED_ACE_TYPE:
                    continue
                if header.AceType != _ACCESS_ALLOWED_ACE_TYPE:
                    return f"its access list has an entry of type {header.AceType} that Two-Key does not read"
                allowed = _ACCESS_ALLOWED_ACE.from_address(ace.value)
                sid = _sid_string(ace.value + _ACCESS_ALLOWED_ACE.SidStart.offset)
                if sid not in trusted and allowed.Mask & (~_HARMLESS if forbidden is None else forbidden):
                    if granted:
                        return f"{_SID_NAMES[sid]} ({sid}) {granted}" if sid in _SID_NAMES else f"{sid} {granted}"
                    return f"{sid} has access to it"
            return None
        finally:
            _k32.LocalFree(descriptor)


def open_nofollow(path, flags: int = os.O_RDONLY) -> int:
    """``os.open`` that refuses a symlink (and on Windows a junction or other reparse point) as the last part."""
    if not WINDOWS:
        return os.open(path, flags | O_NOFOLLOW)
    return _create_file(path, flags, None)  # pragma: no cover


def create_new(path, flags: int = os.O_WRONLY, *, owner_only: bool = True) -> int:
    """Create ``path``; an existing file or symlink is FileExistsError, never an overwrite.

    ``owner_only`` (the default) makes it readable by its owner only from the first byte: mode 0600 on
    POSIX, the protected access list on Windows. Otherwise mode 0644 and, on Windows, the folder's
    inherited access list.
    """
    flags |= os.O_CREAT | os.O_EXCL
    if not WINDOWS:
        return os.open(path, flags | O_NOFOLLOW, 0o600 if owner_only else 0o644)
    return _create_file(path, flags, _owner_only_sddl(False) if owner_only else None)  # pragma: no cover


def open_lock_file(path) -> int:
    """Open (creating if needed) a lock file for :func:`lock`."""
    if not WINDOWS:
        return os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    return _create_file(path, os.O_CREAT | os.O_RDWR, _owner_only_sddl(False))  # pragma: no cover


def access_problem(fd: int, st: os.stat_result | None = None) -> str | None:
    """Why the open file ``fd`` is not owner-only, or None. Checked on the descriptor, so it cannot be swapped.

    POSIX: any group or other mode bit. Windows: an owner, or an "allow" entry with more than metadata
    access, other than the current user, SYSTEM, or Administrators.
    """
    if not WINDOWS:
        st = os.fstat(fd) if st is None else st
        return "readable by group or others" if st.st_mode & 0o077 else None
    return _access_problem_handle(msvcrt.get_osfhandle(fd))  # pragma: no cover


def fix_hint(path) -> str:
    """The command that makes ``path`` owner-only, for an error message."""
    if not WINDOWS:
        return f"chmod 600 {path}"
    return f'icacls "{path}" /inheritance:r /grant:r "%USERNAME%":F'  # pragma: no cover


def insecure(path, problem: str) -> str:
    """The text after a ``*_insecure:`` reason code. On POSIX, the same words as before 0.6.0."""
    if not WINDOWS:
        return f"{path} is {problem}; chmod 600 it"
    return f"{path} is not private to you: {problem}; run {fix_hint(path)}"  # pragma: no cover


def owner_only_dir(path) -> None:
    """Restrict a directory Two-Key owns to its owner: mode 0700, or a protected inheritable access list."""
    if not WINDOWS:
        # Owner only (0o700): the rule's suggested 0o644 would let others read this key directory.
        os.chmod(path, 0o700)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        return
    with _Descriptor(_owner_only_sddl(True)) as descriptor:  # pragma: no cover
        rc = _adv.SetNamedSecurityInfoW(os.fspath(path), _SE_FILE_OBJECT,
                                        _DACL_SECURITY_INFORMATION | _PROTECTED_DACL_SECURITY_INFORMATION,
                                        None, None, descriptor.dacl(), None)
        if rc:
            raise _error(rc, path)


def is_owner_only_dir(path) -> bool:
    """Whether a directory is restricted to its owner (for tests and reports)."""
    if not WINDOWS:
        return stat.S_IMODE(os.stat(path).st_mode) == 0o700
    fd = _create_file_dir(path)  # pragma: no cover
    try:  # pragma: no cover
        return _access_problem_handle(msvcrt.get_osfhandle(fd)) is None
    finally:  # pragma: no cover
        os.close(fd)


if WINDOWS:  # pragma: no cover
    _FILE_FLAG_BACKUP_SEMANTICS = 0x02000000

    def _create_file_dir(path) -> int:
        handle = _k32.CreateFileW(os.fspath(path), _READ_CONTROL, _FILE_SHARE_ALL, None, _OPEN_EXISTING,
                                  _FILE_FLAG_BACKUP_SEMANTICS, None)
        if handle == _INVALID_HANDLE or handle is None:
            raise _last_error(path)
        return msvcrt.open_osfhandle(handle, os.O_RDONLY)


def lock(fd: int) -> None:
    """Take an exclusive, blocking, cross-process lock on ``fd``."""
    if not WINDOWS:
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_EX)
        return
    overlapped = _OVERLAPPED()  # pragma: no cover
    if not _k32.LockFileEx(msvcrt.get_osfhandle(fd), _LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0,  # pragma: no cover
                           ctypes.byref(overlapped)):
        raise _last_error()


def unlock(fd: int) -> None:
    if not WINDOWS:
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_UN)
        return
    overlapped = _OVERLAPPED()  # pragma: no cover
    if not _k32.UnlockFileEx(msvcrt.get_osfhandle(fd), 0, 1, 0, ctypes.byref(overlapped)):  # pragma: no cover
        raise _last_error()


def inside(path, directory) -> bool:
    """Whether ``path`` is ``directory`` or under it, after resolving links, case, and 8.3 short names."""
    p = os.path.normcase(os.path.realpath(path))
    d = os.path.normcase(os.path.realpath(directory))
    return p == d or p.startswith(d.rstrip("\\/") + os.sep)


def replace(src, dst, *, attempts: int = 20, delay: float = 0.05) -> None:
    """``os.replace``; on Windows, retried briefly while another process holds ``dst`` open (bounded)."""
    if not WINDOWS:
        os.replace(src, dst)
        return
    for attempt in range(attempts):  # pragma: no cover
        try:
            os.replace(src, dst)
            return
        except PermissionError as e:
            if getattr(e, "winerror", None) not in _SHARING_VIOLATION or attempt == attempts - 1:
                raise
            time.sleep(delay)


def fsync_dir(path) -> None:
    """Flush a directory entry to disk. POSIX only: Windows cannot open a directory with ``os.open``, and
    NTFS journals the rename itself."""
    if WINDOWS:  # pragma: no cover
        return
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def is_link(path) -> bool:
    """A symlink, or on Windows any reparse point (a junction, too), as the last part of ``path``."""
    if os.path.islink(path):
        return True
    if not WINDOWS:
        return False
    try:  # pragma: no cover
        return bool(os.lstat(path).st_file_attributes & 0x400)
    except OSError:  # pragma: no cover
        return False


def dir_write_problem(path) -> str | None:
    """Why accounts other than the owner can add or remove entries in a directory, or None.

    POSIX: the group or other write bit. Windows: an "allow" entry with a write right for an account other
    than the current user, SYSTEM, or Administrators.
    """
    if not WINDOWS:
        return "writable by group or others" if os.lstat(path).st_mode & 0o022 else None
    # GENERIC_ALL, GENERIC_WRITE, WRITE_OWNER, WRITE_DAC, DELETE, delete child, add subdirectory, add file
    write = 0x10000000 | 0x40000000 | 0x80000 | 0x40000 | 0x10000 | 0x40 | 0x4 | 0x2  # pragma: no cover
    fd = _create_file_dir(path)  # pragma: no cover
    try:  # pragma: no cover
        return _access_problem_handle(msvcrt.get_osfhandle(fd), write)
    finally:  # pragma: no cover
        os.close(fd)


if WINDOWS:  # pragma: no cover
    # GENERIC_ALL, GENERIC_WRITE, WRITE_OWNER, WRITE_DAC, DELETE, delete child, add subdirectory, add file
    _WRITE_RIGHTS = 0x10000000 | 0x40000000 | 0x80000 | 0x40000 | 0x10000 | 0x40 | 0x4 | 0x2
    # What it takes to rename or remove an entry: GENERIC_ALL, WRITE_OWNER, WRITE_DAC, DELETE, delete child.
    _RENAME_RIGHTS = 0x10000000 | 0x80000 | 0x40000 | 0x10000 | 0x40


def _posix_account(uid: int) -> str:
    try:
        import pwd
        return f"{pwd.getpwuid(uid).pw_name} (uid {uid})"
    except (ImportError, KeyError):
        return f"uid {uid}"


def _posix_group(gid: int) -> str:
    try:
        import grp
        return f"{grp.getgrgid(gid).gr_name} (gid {gid})"
    except (ImportError, KeyError):
        return f"gid {gid}"


def write_problem(path, rule: str = "file") -> str | None:
    """Why an account other than this process's user could change ``path``, or None. Follows links.

    ``rule`` is what matters about ``path``: ``file``, its contents; ``folder``, adding, removing, or renaming
    its entries; ``parent``, renaming or removing an entry in it, which a POSIX sticky bit (or on Windows, the
    right to add entries only) does not allow. Root, and on Windows SYSTEM, Administrators, and
    TrustedInstaller, can change anything anyway, so they are not counted.

    POSIX: an owner other than this user or root, the other write bit, or the group write bit for any group
    but 0 (Two-Key cannot list a group's members reliably). Windows: an owner, or an "allow" entry with a
    write right, other than this user or those accounts.
    """
    if not WINDOWS:
        st = os.stat(path)
        if st.st_uid not in (0, os.geteuid()):
            return f"owned by {_posix_account(st.st_uid)}"
        if rule == "parent" and stat.S_ISDIR(st.st_mode) and st.st_mode & stat.S_ISVTX:
            return None
        if st.st_mode & stat.S_IWOTH:
            return "writable by everyone"
        if st.st_mode & stat.S_IWGRP and st.st_gid != 0:
            return f"writable by group {_posix_group(st.st_gid)}"
        return None
    fd = _create_file_dir(path)  # pragma: no cover
    try:  # pragma: no cover
        return _access_problem_handle(msvcrt.get_osfhandle(fd),
                                      _RENAME_RIGHTS if rule == "parent" else _WRITE_RIGHTS, owner=True,
                                      also_trusted=(TRUSTED_INSTALLER_SID,), granted="can change it")
    finally:  # pragma: no cover
        os.close(fd)


def resolve_program(name: str) -> str:
    """The program to start for a command's first word. On Windows, found through PATH and PATHEXT with
    ``shutil.which`` (so ``npx`` runs ``npx.cmd``); never through a shell. On POSIX, unchanged."""
    if not WINDOWS:
        return name
    import shutil  # pragma: no cover
    return shutil.which(name) or name  # pragma: no cover
