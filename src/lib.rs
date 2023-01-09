#![no_std]
extern crate alloc;

/// Defines the system interface we use.
pub mod sys;

// Disabled intentionally. Not implemented.
#[cfg(feature = "elf")]
pub mod elf;

pub struct XdpQueryOpts {
    pub prog_id: u32,
    pub drv_prog_id: u32,
    pub hw_prog_id: u32,
    pub skb_prog_id: u32,
    pub attach_mod: u8,
}

/// An established, configured netlink socket.
pub struct Netlink {
    fd: libc::c_int,
}
