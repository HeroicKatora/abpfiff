use alloc::sync::Arc;

/// The table of functions.
#[non_exhaustive]
pub struct SysVTable {
    // for netlink
    pub socket: FnSocket,
    pub setsockopt: FnSetSockOpt,
    pub getsockopt: FnGetSockOpt,
    pub getsockname: FnGetSockName,
    pub bind: FnBind,
    pub recvmsg: FnRecvMsg,
    pub send: FnSend,

    pub getrlimit: FnGetRLimit,
    pub setrlimit: FnSetRLimit,
    pub sysconf: FnSysconf,
    pub open: FnOpen,
    pub close: FnClose,
    /* mmap, munmap */
    // mkdir, unlink, for pin
    // statfs

    // Unknown for perf/trace
    // But includes syscall(__NR_perf_event_open
    pub errno_location: FnErrnoLocation,
    pub bpf: FnSysBpf,
}

#[derive(Clone)]
pub struct ArcTable(Arc<dyn AsRef<SysVTable> + Send + Sync>);

// Glibc strikes again: <https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=758911>
// Author didn't even make 'better error reporting' precise. _how_ better?
#[allow(non_camel_case_types)]
#[cfg(target_env = "gnu")]
pub type rlimit_resource = libc::__rlimit_resource_t;
#[cfg(not(target_env = "gnu"))] // How posix intended..
pub type rlimit_resource = libc::c_int;

use libc::{c_char, c_int, c_long, c_uint, c_void, msghdr, size_t, sockaddr, socklen_t, ssize_t};

use crate::{Errno, OwnedFd};

pub type FnSocket = unsafe extern "C" fn(c_int, c_int, c_int) -> c_int;
pub type FnSetSockOpt =
    unsafe extern "C" fn(c_int, c_int, c_int, *const c_void, socklen_t) -> c_int;
pub type FnGetSockOpt =
    unsafe extern "C" fn(c_int, c_int, c_int, *mut c_void, *mut socklen_t) -> c_int;
pub type FnGetSockName = unsafe extern "C" fn(c_int, *mut sockaddr, *mut socklen_t) -> c_int;
pub type FnBind = unsafe extern "C" fn(c_int, *const sockaddr, socklen_t) -> c_int;
pub type FnRecvMsg = unsafe extern "C" fn(c_int, *mut msghdr, c_int) -> ssize_t;
pub type FnSend = unsafe extern "C" fn(c_int, *const c_void, size_t, c_int) -> ssize_t;

pub type FnGetRLimit = unsafe extern "C" fn(rlimit_resource, *mut libc::rlimit) -> c_int;
pub type FnSetRLimit = unsafe extern "C" fn(rlimit_resource, *const libc::rlimit) -> c_int;
pub type FnSysconf = unsafe extern "C" fn(c_int) -> c_long;

pub type FnOpen = unsafe extern "C" fn(*const c_char, c_int, libc::mode_t) -> c_int;
pub type FnClose = unsafe extern "C" fn(c_int) -> c_int;

pub type FnErrnoLocation = unsafe extern "C" fn() -> *mut c_int;

pub type FnSysBpf = unsafe extern "C" fn(c_long, attr: *mut c_void, size: c_uint) -> c_long;

impl SysVTable {
    /// Create a system table pointing to static (libc) data.
    pub fn new() -> ArcTable {
        unsafe extern "C" fn _open(msg: *const c_char, flags: c_int, mode: libc::mode_t) -> c_int {
            libc::open(msg, flags, mode)
        }

        static SYS: SysVTable = SysVTable {
            socket: libc::socket,

            setsockopt: libc::setsockopt,
            getsockopt: libc::getsockopt,
            getsockname: libc::getsockname,
            bind: libc::bind,
            recvmsg: libc::recvmsg,
            send: libc::send,

            getrlimit: libc::getrlimit,
            setrlimit: libc::setrlimit,
            sysconf: libc::sysconf,
            open: _open,
            close: libc::close,

            errno_location: libc::__errno_location,

            bpf: sys_bpf,
        };

        struct FakeSys;

        impl AsRef<SysVTable> for FakeSys {
            fn as_ref(&self) -> &SysVTable {
                &SYS
            }
        }

        ArcTable(Arc::new(FakeSys))
    }

    pub fn errno(&self) -> Errno {
        Errno(unsafe { *(self.errno_location)() })
    }

    pub(crate) fn mk_errno(&self, err: libc::c_int) -> Errno {
        Errno(err)
    }

    pub(crate) fn bpf_err(&self, err: LibBpfErrno) -> Errno {
        Errno(err as libc::c_int)
    }
}

impl ArcTable {
    /// Create a custom `ArcTable`.
    ///
    /// # Safety
    ///
    /// The caller guarantees that the function table only contains functions that assume no more
    /// of their inputs than the system functions, and that their return values are as specified.
    /// In particular, errors are signaled only via defined error codes (and `errno` where so
    /// defined) and non-error returns initialize all outputs that need to be initialized.
    ///
    /// In simple words: proxying a real syscall is good, don't assume you can do arbitrary things
    /// with any pointer passed. Behave like a specified system.
    pub unsafe fn new<Sys>(arc: Arc<Sys>) -> Self
    where
        Sys: AsRef<SysVTable> + Send + Sync + 'static,
    {
        ArcTable(arc)
    }

    pub(crate) fn wrap_fd(&self, fd: libc::c_int) -> OwnedFd {
        OwnedFd(fd, self.clone())
    }
}

/// automatically deref to the table definition.
impl core::ops::Deref for ArcTable {
    type Target = SysVTable;
    fn deref(&self) -> &SysVTable {
        (*self.0).as_ref()
    }
}

/// <linux/netlink.h>
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NlMsgHdr {
    /** Length of message including header and padding. */
    pub nlmsg_len: u32,
    /** Message type (content type) */
    pub nlmsg_type: u16,
    /** Message flags */
    pub nlmsg_flags: u16,
    /** Sequence number of message \see core_sk_seq_num. */
    pub nlmsg_seq: u32,
    /** Netlink port */
    pub nlmsg_pid: u32,
}

unsafe impl bytemuck::Zeroable for NlMsgHdr {}
unsafe impl bytemuck::Pod for NlMsgHdr {}

impl NlMsgHdr {
    // `NlMsgHdr::nlmsg_flags`
    pub const NLM_F_REQUEST: u16 = 0x01; /* It is request message. */
    pub const NLM_F_MULTI: u16 = 0x02; /* Multipart message, terminated by NLMSG_DONE */
    pub const NLM_F_ACK: u16 = 0x04; /* Reply with ack, with zero or error code */
    pub const NLM_F_ECHO: u16 = 0x08; /* Echo this request */
    pub const NLM_F_DUMP_INTR: u16 = 0x10; /* Dump was inconsistent due to sequence change */
    pub const NLM_F_DUMP_FILTERED: u16 = 0x20; /* Dump was filtered as requested */

    /* Modifiers to GET request */
    pub const NLM_F_ROOT: u16 = 0x100; /* specify tree root */
    pub const NLM_F_MATCH: u16 = 0x200; /* return all matching */
    pub const NLM_F_ATOMIC: u16 = 0x400; /* atomic GET */
    pub const NLM_F_DUMP: u16 = (Self::NLM_F_ROOT | Self::NLM_F_MATCH);

    /* Modifiers to NEW request */
    pub const NLM_F_REPLACE: u16 = 0x100; /* Override existing  */
    pub const NLM_F_EXCL: u16 = 0x200; /* Do not touch, if it exists */
    pub const NLM_F_CREATE: u16 = 0x400; /* Create, if it does not exist */
    pub const NLM_F_APPEND: u16 = 0x800; /* Add to end of list  */

    /* Modifiers to DELETE request */
    pub const NLM_F_NONREC: u16 = 0x100; /* Do not delete recursively */

    /* Flags for ACK message */
    pub const NLM_F_CAPPED: u16 = 0x100; /* request was capped */
    pub const NLM_F_ACK_TLVS: u16 = 0x200; /* extended ACK TVLs were included */

    pub const NLMSG_NOOP: u16 = 0x1;
    pub const NLMSG_ERROR: u16 = 0x2;
    pub const NLMSG_DONE: u16 = 0x3;
    pub const NLMSG_OVERRUN: u16 = 0x4;
    // Reserve messages
    pub const NLMSG_MIN_TYPE: u16 = 0x10;
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NlMsgErr {
    pub error: libc::c_int,
    pub msg: NlMsgHdr,
}

unsafe impl bytemuck::Zeroable for NlMsgErr {}
unsafe impl bytemuck::Pod for NlMsgErr {}

/// <linux/rtnetlink.h>
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct IfInfoMsg {
    pub ifi_family: libc::c_uchar,
    pub __ifi_pad: libc::c_uchar,
    pub ifi_type: libc::c_ushort, /* ARPHRD_* */
    pub ifi_index: libc::c_int,   /* Link index */
    pub ifi_flags: libc::c_uint,  /* IFF_* flags */
    pub ifi_change: libc::c_uint, /* IFF_* change mask */
}

unsafe impl bytemuck::Zeroable for IfInfoMsg {}
unsafe impl bytemuck::Pod for IfInfoMsg {}

/// <linux/rtnetlink.h>
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TcMsg {
    pub tcm_family: libc::c_uchar,
    pub _tcm_pad1: libc::c_uchar,
    pub _tcm_pad2: libc::c_ushort,
    pub tcm_ifindex: libc::c_int,
    pub tcm_handle: u32,
    pub tcm_parent: u32,
    /* tcm_block_index is used instead of tcm_parent
     * in case tcm_ifindex == TCM_IFINDEX_MAGIC_BLOCK
     */
    pub tcm_info: u32,
}

unsafe impl bytemuck::Zeroable for TcMsg {}
unsafe impl bytemuck::NoUninit for TcMsg {}

#[repr(C)]
#[repr(align(4))]
#[derive(Clone, Copy, Debug)]
pub struct NlIfInfoReq {
    pub hdr: NlMsgHdr,
    pub msg: IfInfoMsg,
}

unsafe impl bytemuck::Zeroable for NlIfInfoReq {}
unsafe impl bytemuck::NoUninit for NlIfInfoReq {}

#[repr(C)]
#[repr(align(4))]
#[derive(Clone, Copy, Debug)]
pub struct NlTcReq {
    pub hdr: NlMsgHdr,
    pub msg: TcMsg,
}

unsafe impl bytemuck::Zeroable for NlTcReq {}
unsafe impl bytemuck::NoUninit for NlTcReq {}

#[repr(C)]
pub struct SockaddrNl {
    pub nl_family: libc::sa_family_t,
    pub nl_pad: libc::c_ushort,
    pub nl_pid: u32,
    pub nl_groups: u32,
}

/// Do the `bpf` syscall.
///
/// The caller guarantees that their arguments conform to the expected pointers, i.e. the cmd type
/// dictates the layout for `attr` and expected size.
unsafe extern "C" fn sys_bpf(cmd: c_long, attr: *mut c_void, size: c_uint) -> c_long {
    return libc::syscall(libc::SYS_bpf, cmd, attr, size);
}

#[repr(i32)]
#[allow(non_camel_case_types, dead_code)]
pub(crate) enum LibBpfErrno {
    /* Something wrong in libelf */
    LIBBPF_ERRNO__LIBELF = 4000,
    LIBBPF_ERRNO__FORMAT,   /* BPF object format invalid */
    LIBBPF_ERRNO__KVERSION, /* Incorrect or no 'version' section */
    LIBBPF_ERRNO__ENDIAN,   /* Endian mismatch */
    LIBBPF_ERRNO__INTERNAL, /* Internal error in libbpf */
    LIBBPF_ERRNO__RELOC,    /* Relocation failed */
    LIBBPF_ERRNO__LOAD,     /* Load program failure for unknown reason */
    LIBBPF_ERRNO__VERIFY,   /* Kernel verifier blocks program loading */
    LIBBPF_ERRNO__PROG2BIG, /* Program too big */
    LIBBPF_ERRNO__KVER,     /* Incorrect kernel version */
    LIBBPF_ERRNO__PROGTYPE, /* Kernel doesn't support this program type */
    LIBBPF_ERRNO__WRNGPID,  /* Wrong pid in netlink message */
    LIBBPF_ERRNO__INVSEQ,   /* Invalid netlink sequence */
    LIBBPF_ERRNO__NLPARSE,  /* netlink parsing error */
}
