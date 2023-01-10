use crate::sys::{ArcTable, SockaddrNl};
use crate::{Errno, Netlink, OwnedFd};

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

    /// Receive one message, may be part of a multipart.
    fn recvmsg_part(&mut self) -> MsgPart<'_> {
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
        todo!()
    }

    /// Synchronously query information of an XDP interface.
    pub fn bpf_xdp_query(&mut self) {}
}

struct MsgPart<'a> {
    buf: &'a [u8],
}
