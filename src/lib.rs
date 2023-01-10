#![no_std]
extern crate alloc;

/// Implementation of netlink operations.
mod netlink;
/// Defines the system interface we use.
pub mod sys;

// Disabled intentionally. Not implemented.
#[cfg(feature = "elf")]
pub mod elf;

pub struct XdpQuery {
    pub prog_id: u32,
    pub drv_prog_id: u32,
    pub hw_prog_id: u32,
    pub skb_prog_id: u32,
    pub attach_mod: u8,
}

/// An established, configured netlink socket.
pub struct Netlink {
    pid: u32,
    sock: OwnedFd,
    seq: u32,
    buf: alloc::vec::Vec<u8>,
}

pub struct Object {
    object_id: u64,
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

impl Drop for OwnedFd {
    fn drop(&mut self) {
        let _ = unsafe { (self.1.close)(self.0) };
    }
}
