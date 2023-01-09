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
}

// Glibc strikes again: <https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=758911>
// Author didn't even make 'better error reporting' precise. _how_ better?
#[allow(non_camel_case_types)]

#[cfg(target_env = "gnu")]
pub type rlimit_resource = libc::__rlimit_resource_t;
#[cfg(not(target_env = "gnu"))] // How posix intended..
pub type rlimit_resource = libc::c_int;

use libc::{c_char, c_int, c_long, c_void, msghdr, size_t, sockaddr, socklen_t, ssize_t};

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

impl SysVTable {
    /// Create a system table pointing to static (libc) data.
    pub fn new() -> Arc<dyn AsRef<Self>> {
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
        };

        struct FakeSys;

        impl AsRef<SysVTable> for FakeSys {
            fn as_ref(&self) -> &SysVTable {
                &SYS
            }
        }

        Arc::new(FakeSys)
    }
}

/// <linux/netlink.h>
#[repr(C)]
pub struct NlMsgHdr {
    /** Length of message including header and padding. */
    nlmsg_len: u32,
    /** Message type (content type) */
    nlmsg_type: u16,
    /** Message flags */
    nlmsg_flags: u16,
    /** Sequence number of message \see core_sk_seq_num. */
    nlmsg_seq: u32,
    /** Netlink port */
    nlmsg_pid: u32,
}

/// <linux/rtnetlink.h>
#[repr(C)]
pub struct IfInfoMsg {
    ifi_family: libc::c_uchar,
    __ifi_pad: libc::c_uchar,
    ifi_type: libc::c_ushort, /* ARPHRD_* */
    ifi_index: libc::c_int,   /* Link index	*/
    ifi_flags: libc::c_uint,  /* IFF_* flags	*/
    ifi_change: libc::c_uint, /* IFF_* change mask */
}

/// <linux/rtnetlink.h>
#[repr(C)]
pub struct TcMsg {
    tcm_family: libc::c_uchar,
    _tcm_pad1: libc::c_uchar,
    _tcm_pad2: libc::c_ushort,
    tcm_ifindex: libc::c_int,
    tcm_handle: u32,
    tcm_parent: u32,
    /* tcm_block_index is used instead of tcm_parent
     * in case tcm_ifindex == TCM_IFINDEX_MAGIC_BLOCK
     */
    // #define tcm_block_index tcm_parent
    tcm_info: u32,
}

#[repr(C)]
#[repr(align(4))]
pub struct NlIfInfoReq {
    hdr: NlMsgHdr,
    msg: IfInfoMsg,
}

#[repr(C)]
#[repr(align(4))]
pub struct NlTcReq {
    hdr: NlMsgHdr,
    msg: TcMsg,
}
