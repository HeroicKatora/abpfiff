#![no_std]
extern crate alloc;

macro_rules! eprint {
    ($msg:literal, $($arg:expr),*) => {
        match ::alloc::format!($msg, $($arg),*) {
            msg => {
                unsafe { libc::write(2, msg.as_bytes().as_ptr() as *const _, msg.len()) };
                $($arg)*
            }
        }
    }
}

pub mod bpf;
/// Implementation of netlink operations.
mod netlink;
mod nlattr;
/// Defines the system interface we use.
pub mod sys;

// Disabled intentionally. Not implemented.
#[cfg(feature = "elf")]
pub mod elf;

/// Entrypoint, query object IDs attached to a network interface.
#[repr(C)]
#[derive(Debug, Default)]
pub struct XdpQuery {
    pub prog_id: u32,
    pub drv_prog_id: u32,
    pub hw_prog_id: u32,
    pub skb_prog_id: u32,
    pub attach_mode: u8,
}

#[repr(C)]
pub struct BpfProgQuery<'a> {
    pub target_fd: u32,
    pub attach_type: u32,
    pub query_flags: u32,
    pub attach_flags: u32,
    /// Pointer to a buffer for prog ids, must be aligned.
    /// Kernel assumes it to be valid for `prog_cnt` elements on entry.
    pub prog_ids: &'a mut [u64],
}

/// An established, configured netlink socket.
pub struct Netlink {
    pid: u32,
    sock: OwnedFd,
    seq: u32,
    buf: alloc::vec::Vec<u8>,
}

pub use netlink::NetlinkRecvBuffer;

/// An abstract reference to a BPF object.
pub struct Object {
    pub id: core::num::NonZeroU32,
}

pub struct ProgramFd {
    fd: OwnedFd,
}

/// Encapsulates a map.
///
/// Initially, the `MapFd` does not know the actual size of keys and values of this map. However,
/// since this is a creation-time constant we can discover it later. Before accessing the map you
/// must discover the info once with `Sys
pub struct MapFd {
    fd: OwnedFd,
    /// The number bytes a caller must pass to allow a safe read.
    key_size_access_requirement: Option<u32>,
    /// The number mutable bytes a caller must pass to allow a safe write.
    val_size_access_requirement: Option<u32>,
}

pub struct Xdp {}

pub struct Errno(libc::c_int);

struct OwnedFd(libc::c_int, sys::ArcTable);

pub fn bpf_obj_get_info_by_fd() {}
pub fn bpf_object__find_map_by_name() {}

pub fn bpf_map_get_fd_by_id() {}
pub fn bpf_map_lookup_elem() {}
pub fn bpf_map_update_elem() {}
pub fn bpf_map_delete_elem() {}

impl Errno {
    pub fn get_raw(&self) -> libc::c_int {
        self.0
    }
}

impl Drop for OwnedFd {
    fn drop(&mut self) {
        let _ = unsafe { (self.1.close)(self.0) };
    }
}
