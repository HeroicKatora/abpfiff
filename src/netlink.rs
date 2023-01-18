use alloc::vec::Vec;
use bytemuck::Zeroable;
use core::ops::ControlFlow;

use crate::nlattr;
use crate::sys::{
    ArcTable, IfInfoMsg, LibBpfErrno, NlIfInfoReq, NlMsgErr, NlMsgHdr, NlTcReq, SockaddrNl,
};
use crate::{Errno, Netlink, OwnedFd, XdpQuery};

pub struct NetlinkRecvBuffer {
    iovec: libc::iovec,
    mhdr: libc::msghdr,
    /// Using `u32` due to align >= 4 requirement.
    buf: Vec<u32>,
    /// The expected sequence number.
    seq: u32,
}

/// Just for reference, the command constants.
#[allow(dead_code)]
impl Netlink {
    const ADD_MEMBERSHIP: libc::c_int = 1;
    const DROP_MEMBERSHIP: libc::c_int = 2;
    const PKTINFO: libc::c_int = 3;
    const BROADCAST_ERROR: libc::c_int = 4;
    const NO_ENOBUFS: libc::c_int = 5;
    const RX_RING: libc::c_int = 6;
    const TX_RING: libc::c_int = 7;
    const LISTEN_ALL_NSID: libc::c_int = 8;
    const LIST_MEMBERSHIPS: libc::c_int = 9;
    const CAP_ACK: libc::c_int = 10;
    const EXT_ACK: libc::c_int = 11;
    const GET_STRICT_CHK: libc::c_int = 12;
}

impl Netlink {
    pub fn open(sys: ArcTable) -> Result<Self, Errno> {
        let sock = unsafe {
            (sys.socket)(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };

        if sock < 0 {
            return Err(sys.errno());
        }

        let sock = OwnedFd(sock, sys.clone());

        if {
            let one: libc::c_int = 1;
            let size = core::mem::size_of_val(&one) as libc::socklen_t;

            unsafe {
                (sys.setsockopt)(
                    sock.0,
                    libc::SOL_NETLINK,
                    Self::EXT_ACK,
                    (&one) as *const _ as *const libc::c_void,
                    size,
                )
            }
        } < 0
        {}

        let mut sockaddr_nl = SockaddrNl {
            nl_family: libc::AF_NETLINK as libc::sa_family_t,
            nl_pad: 0,
            nl_pid: 0,
            nl_groups: 0,
        };

        if {
            unsafe {
                (sys.bind)(
                    sock.0,
                    (&mut sockaddr_nl) as *mut _ as *mut libc::sockaddr,
                    core::mem::size_of_val(&sockaddr_nl) as libc::socklen_t,
                )
            }
        } < 0
        {
            return Err(sys.errno());
        }

        if {
            let mut addrlen = core::mem::size_of_val(&sockaddr_nl) as libc::socklen_t;
            unsafe {
                (sys.getsockname)(
                    sock.0,
                    (&mut sockaddr_nl) as *mut _ as *mut libc::sockaddr,
                    &mut addrlen,
                )
            }
        } < 0
        {
            return Err(sys.errno());
        }

        let pid = sockaddr_nl.nl_pid;
        let seq = 0u32;
        let buf = alloc::vec::Vec::new();

        Ok(Netlink {
            sock,
            pid,
            seq,
            buf,
        })
    }

    pub fn sys(&self) -> &ArcTable {
        &self.sock.1
    }

    pub fn xdp_query(
        &mut self,
        ifindex: u32,
        buf: &mut NetlinkRecvBuffer,
    ) -> Result<XdpQuery, Errno> {
        let mut req = NlIfInfoReq {
            hdr: NlMsgHdr {
                nlmsg_type: libc::RTM_GETLINK,
                nlmsg_flags: NlMsgHdr::NLM_F_DUMP | NlMsgHdr::NLM_F_REQUEST,
                ..NlMsgHdr::zeroed()
            },
            msg: IfInfoMsg {
                ifi_family: libc::AF_PACKET as u8,
                ..IfInfoMsg::zeroed()
            },
        };

        let sys = self.sys().clone();
        let mut query = XdpQuery::default();
        let mut parse_err = Ok(());

        self.sendmsg_if_info(&mut req, buf)?;
        self.recvmsg_multi(buf, |hdr, data| {
            Self::link_nlmsg_parse(
                &sys,
                hdr,
                data,
                |hdr, attr| {
                    if hdr.ifi_index as u32 != ifindex {
                        // eprint!("Nested Data: {:?}\n", attr[nlattr::IflaType::IFLA_XDP as usize].data);
                        return Ok(());
                    }

                    // eprint!("Nested Data: {:?}\n", nlattr::IflaType::IFLA_XDP as usize);
                    // eprint!("Nested Data: {:?}\n", attr[nlattr::IflaType::IFLA_XDP as usize].data);

                    let nested = match attr[nlattr::IflaType::IFLA_XDP as usize].data {
                        Some(data) => data,
                        None => return Ok(()),
                    };

                    for attr in &mut attr[..nlattr::IFLA_XDP_MAX] {
                        *attr = nlattr::Attr::default();
                    }

                    nlattr::parse(&mut attr[..nlattr::IFLA_XDP_MAX], nested)?;
                    // eprint!("Nested: {:?}\n", &attr[..nlattr::IFLA_XDP_MAX]);

                    if !attr[nlattr::IflaXdp::IFLA_XDP_ATTACHED as usize].is_set() {
                        return Ok(());
                    }

                    query.attach_mode =
                        attr[nlattr::IflaXdp::IFLA_XDP_ATTACHED as usize].getattr_u8()?;

                    if query.attach_mode == 0 {
                        return Ok(());
                    }

                    if attr[nlattr::IflaXdp::IFLA_XDP_PROG_ID as usize].is_set() {
                        query.prog_id =
                            attr[nlattr::IflaXdp::IFLA_XDP_PROG_ID as usize].getattr_u32()?;
                    }

                    if attr[nlattr::IflaXdp::IFLA_XDP_SKB_PROG_ID as usize].is_set() {
                        query.skb_prog_id =
                            attr[nlattr::IflaXdp::IFLA_XDP_SKB_PROG_ID as usize].getattr_u32()?;
                    }

                    if attr[nlattr::IflaXdp::IFLA_XDP_DRV_PROG_ID as usize].is_set() {
                        query.drv_prog_id =
                            attr[nlattr::IflaXdp::IFLA_XDP_DRV_PROG_ID as usize].getattr_u32()?;
                    }

                    if attr[nlattr::IflaXdp::IFLA_XDP_HW_PROG_ID as usize].is_set() {
                        query.hw_prog_id =
                            attr[nlattr::IflaXdp::IFLA_XDP_HW_PROG_ID as usize].getattr_u32()?;
                    }

                    Ok(())
                },
                &mut parse_err,
            )
        })?;

        Ok(query)
    }

    /** Low-level methods to interact directly with Netlink. */
    pub fn sendmsg_if_info(
        &mut self,
        req: &mut NlIfInfoReq,
        buf: &mut NetlinkRecvBuffer,
    ) -> Result<(), Errno> {
        let nlmsg_len = core::mem::size_of_val(req);
        req.hdr.nlmsg_pid = 0;
        req.hdr.nlmsg_seq = self.seq;
        req.hdr.nlmsg_len = nlmsg_len as u32;
        unsafe { self.sendmsg_after_len(req as *mut _ as *const _, nlmsg_len, buf) }
    }

    pub fn sendmsg_tc(
        &mut self,
        req: &mut NlTcReq,
        buf: &mut NetlinkRecvBuffer,
    ) -> Result<(), Errno> {
        let nlmsg_len = core::mem::size_of_val(req);
        req.hdr.nlmsg_pid = 0;
        req.hdr.nlmsg_seq = self.seq;
        req.hdr.nlmsg_len = nlmsg_len as u32;
        unsafe { self.sendmsg_after_len(req as *mut _ as *const _, nlmsg_len, buf) }
    }

    pub(crate) unsafe fn sendmsg_after_len(
        &mut self,
        req: *const NlMsgHdr,
        nlmsg_len: usize,
        buf: &mut NetlinkRecvBuffer,
    ) -> Result<(), Errno> {
        buf.set_seq(self.seq);
        self.seq += 1;

        if unsafe {
            (self.sys().send)(
                self.sock.0,
                req as *const _ as *const libc::c_void,
                nlmsg_len,
                0,
            )
        } < 0
        {
            Err(self.sys().errno())
        } else {
            Ok(())
        }
    }

    pub fn recvmsg_multi(
        &self,
        buffer: &mut NetlinkRecvBuffer,
        fn_: impl FnMut(&NlMsgHdr, &[u8]) -> ControlFlow<()>,
    ) -> Result<(), Errno> {
        buffer.recvmsg_multi(self, fn_)
    }

    /// `__dump_link_nlattr`.
    fn link_nlmsg_parse<F>(
        sys: &ArcTable,
        _: &NlMsgHdr,
        data: &[u8],
        mut f: F,
        err: &mut Result<(), Errno>,
    ) -> ControlFlow<()>
    where
        F: FnMut(&IfInfoMsg, &mut [nlattr::Attr]) -> Result<(), LibBpfErrno>,
    {
        if err.is_err() {
            return ControlFlow::Break(());
        }

        let ifohdr = match data.get(..core::mem::size_of::<IfInfoMsg>()) {
            None => {
                *err = Err(sys.bpf_err(LibBpfErrno::LIBBPF_ERRNO__NLPARSE));
                return ControlFlow::Break(());
            }
            Some(msg) => msg,
        };

        let data = &data[core::mem::size_of::<IfInfoMsg>()..];
        let ifohdr: &IfInfoMsg = match bytemuck::try_from_bytes(ifohdr) {
            Err(_) => {
                *err = Err(sys.bpf_err(LibBpfErrno::LIBBPF_ERRNO__NLPARSE));
                return ControlFlow::Break(());
            }
            Ok(msg) => msg,
        };

        let mut nlattr = [nlattr::Attr::default(); nlattr::IFLA_MAX + 1];
        match nlattr::parse(&mut nlattr, data) {
            Err(no) => {
                *err = Err(sys.bpf_err(no));
                return ControlFlow::Break(());
            }
            Ok(len) => len,
        }

        match f(ifohdr, &mut nlattr[..]) {
            Err(no) => {
                *err = Err(sys.bpf_err(no));
                return ControlFlow::Break(());
            }
            Ok(len) => len,
        }

        ControlFlow::Continue(())
    }

    fn get_xdp_info() -> ControlFlow<()> {
        ControlFlow::Continue(())
    }
}

impl NetlinkRecvBuffer {
    pub const fn new() -> Self {
        let iovec = libc::iovec {
            iov_base: core::ptr::null_mut(),
            iov_len: 0,
        };

        let mhdr = libc::msghdr {
            msg_iov: core::ptr::null_mut(),
            msg_iovlen: 0,
            msg_control: core::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
            msg_name: core::ptr::null_mut(),
            msg_namelen: 0,
        };

        NetlinkRecvBuffer {
            iovec,
            mhdr,
            buf: Vec::new(),
            seq: 0,
        }
    }

    /// Set the expected sec for `recvmsg_multi`.
    pub fn set_seq(&mut self, seq: u32) {
        self.seq = seq;
    }

    /// Clear the buffer, deallocating its memory in the process.
    pub fn clear(&mut self) {
        let _ = self.buf.split_off(0);
    }

    /// Receive one message, may be part of a multipart.
    fn recvmsg_part(&mut self, from: &Netlink) -> Result<NlMessage<'_>, Errno> {
        /* > Netlink expects that the user buffer will be at least 8kB or a page size of the CPU
         * architecture, whichever is bigger. Particular Netlink families may, however, require a
         * larger buffer. 32kB buffer is recommended for most efficient handling of dumps (larger
         * buffer fits more dumped objects and therefore fewer recvmsg() calls are needed).
         * > -- <https://kernel.org/doc/html/next/userspace-api/netlink/intro.html>
         *
         * We can peek a message as well, then resize the buffer based off the header. Let's do
         * that, just like in libbpf. However, we can preserve that buffer.
         *
         * */
        self.buf.reserve(4096usize.saturating_sub(self.buf.len()));

        let len = unsafe {
            let mhdr = self.prepare_mhdr();
            (from.sock.1.recvmsg)(from.sock.0, mhdr, libc::MSG_PEEK | libc::MSG_TRUNC)
        };

        if len < 0 {
            return Err(from.sock.1.errno());
        }

        self.buf
            .reserve((len as usize).saturating_sub(self.buf.len()));

        let len = unsafe {
            let mhdr = self.prepare_mhdr();
            (from.sock.1.recvmsg)(from.sock.0, mhdr, 0)
        };

        if len < 0 {
            return Err(from.sock.1.errno());
        }

        unsafe { self.buf.set_len(len as usize) };

        Ok(NlMessage {
            buf: self.as_data(len as usize),
            is_multipart_detected: false,
        })
    }

    /// Parse message contents for the expected sequence number.
    ///
    /// The method can return `ControlFlow::Break` to break processing parts of one message, and
    /// continue to the next multipart message if it exists.
    ///
    /// If this returns an error, then the Netlink to the kernel is likely broken or in an invalid
    /// state. Please don't use it afterwards. Recoverable errors (i.e. ignored packets) are
    /// handled internally or via callbacks, not via early return.
    fn recvmsg_multi(
        &mut self,
        from: &Netlink,
        mut fn_: impl FnMut(&NlMsgHdr, &[u8]) -> ControlFlow<()>,
    ) -> Result<(), Errno> {
        let seq = self.seq;

        loop {
            let mut msg = self.recvmsg_part(from)?;
            'parts: while let Some((hdr, data)) = msg.next() {
                if hdr.nlmsg_pid != from.pid {
                    return Err(from.sys().bpf_err(LibBpfErrno::LIBBPF_ERRNO__WRNGPID));
                }

                if hdr.nlmsg_seq < seq {
                    continue;
                }

                if hdr.nlmsg_seq > seq {
                    return Err(from.sys().bpf_err(LibBpfErrno::LIBBPF_ERRNO__INVSEQ));
                }

                match hdr.nlmsg_type {
                    NlMsgHdr::NLMSG_ERROR => {
                        // Huh, this check is missing from the libbpf implementation, just reading
                        // into that part of the message. Guess that's okay because we trust the
                        // kernel? Eh, let's verify and fail with something useful.
                        let err = match bytemuck::try_from_bytes::<NlMsgErr>(data) {
                            Err(_) => {
                                return Err(from.sys().bpf_err(LibBpfErrno::LIBBPF_ERRNO__INTERNAL))
                            }
                            Ok(err) => err,
                        };

                        if err.error == 0 {
                            continue;
                        }

                        return Err(from.sys().mk_errno(err.error));
                    }
                    NlMsgHdr::NLMSG_DONE => {
                        return Ok(());
                    }
                    _ => {}
                }

                match fn_(hdr, data) {
                    ControlFlow::Continue(()) => {}
                    ControlFlow::Break(()) => break 'parts,
                }
            }

            if !msg.is_multipart_detected() {
                return Ok(());
            }
        }
    }

    /// Helper method, ensuring pointers in the raw FFI structs are ready and valid on use.
    fn prepare_mhdr(&mut self) -> &mut libc::msghdr {
        self.iovec.iov_len = self.buf.capacity();
        self.iovec.iov_base = self.buf.as_mut_ptr() as *mut libc::c_void;
        self.mhdr.msg_iovlen = 1;
        self.mhdr.msg_iov = &mut self.iovec;
        &mut self.mhdr
    }

    fn as_data(&self, data: usize) -> &[u8] {
        &bytemuck::cast_slice(self.buf.as_slice())[..data]
    }
}

impl<'a> NlMessage<'a> {
    pub fn next(&mut self) -> Option<(&'a NlMsgHdr, &'a [u8])> {
        let hdr = self.buf.get(..core::mem::size_of::<NlMsgHdr>())?;
        let hdr = bytemuck::try_from_bytes::<NlMsgHdr>(hdr).ok()?;
        self.is_multipart_detected |= (hdr.nlmsg_flags & NlMsgHdr::NLM_F_MULTI) != 0;

        let end = hdr.nlmsg_len as usize;
        let data = self.buf.get(core::mem::size_of::<NlMsgHdr>()..end)?;
        // Round up to 4 as per <linux/netlink.h>
        let offset = (hdr.nlmsg_len + 3) & !3;

        self.buf = self.buf.get(offset as usize..)?;

        Some((hdr, data))
    }

    /// Return true if any of the parts had the multipart flag set.
    pub fn is_multipart_detected(&self) -> bool {
        self.is_multipart_detected
    }
}

/// One full message datagram.
///
/// The message itself contains multiple Netlink portions. May be part of a multipart. _After_
/// iterating over all its nl portions, query `is_multipart_detected()` to find out.
struct NlMessage<'a> {
    buf: &'a [u8],
    is_multipart_detected: bool,
}
