//! Interact with bpf(2).
use crate::{sys::ArcTable, Errno, MapFd, Object, ProgramFd};
use core::num::NonZeroU32;

impl ArcTable {
    pub fn get_progfd_by_id(&self, id: Object) -> Result<ProgramFd, Errno> {
        let fd = self.raw_fd_by_id(id)?;
        let fd = self.wrap_fd(fd);
        Ok(ProgramFd { fd })
    }

    pub fn get_mapfd_by_id(&self, id: Object) -> Result<MapFd, Errno> {
        let fd = self.raw_fd_by_id(id)?;
        let fd = self.wrap_fd(fd);
        Ok(MapFd { fd })
    }

    pub fn get_progfd_info(
        &self,
        prog: &ProgramFd,
        info: &mut BpfProgInfo,
        out: BpfProgOut,
    ) -> Result<usize, Errno> {
        // Ensure not out-ptr is set improperly.
        info.nr_map_ids = 0;
        if let Some(map_ids) = out.map_ids {
            info.nr_map_ids = map_ids.len() as u32;
            info.map_ids = OutAddr(map_ids.as_mut_ptr() as u64);
        }

        info.jited_prog_len = 0;
        info.xlated_prog_len = 0;
        info.nr_line_info = 0;
        info.nr_jited_line_info = 0;
        info.nr_func_info = 0;
        info.nr_jited_ksyms = 0;
        info.nr_jited_func_lens = 0;
        info.nr_prog_tags = 0;

        let data = bytemuck::bytes_of_mut(info);
        let data = bytemuck::cast_slice_mut(data);
        unsafe { self.raw_info_by_fd(prog.as_raw_fd(), data) }
    }

    pub fn get_mapfd_info(&self, prog: &MapFd, info: &mut BpfMapInfo) -> Result<usize, Errno> {
        let data = bytemuck::bytes_of_mut(info);
        let data = bytemuck::cast_slice_mut(data);
        unsafe { self.raw_info_by_fd(prog.as_raw_fd(), data) }
    }

    pub unsafe fn raw_info_by_fd(&self, fd: libc::c_int, info: &mut [u64]) -> Result<usize, Errno> {
        let info_len = u32::try_from(info.len()).unwrap_or(u32::MAX);

        let mut attr = BpfOjbGetInfoByFd {
            fd: fd as u32,
            info_len,
            info: info.as_mut_ptr(),
        };

        let attr_sz = core::mem::size_of_val(&attr) as u32;

        if unsafe {
            (self.bpf)(
                BpfCmd::ObjGetInfoByFd as libc::c_long,
                (&mut attr) as *mut _ as *mut libc::c_void,
                attr_sz,
            )
        } < 0
        {
            return Err(self.errno());
        }

        Ok(attr.info_len.min(info_len) as usize)
    }

    pub fn raw_fd_by_id(&self, id: Object) -> Result<libc::c_int, Errno> {
        todo!()
    }
}

impl ProgramFd {
    pub fn as_raw_fd(&self) -> libc::c_int {
        self.fd.0
    }
}

impl MapFd {
    pub fn as_raw_fd(&self) -> libc::c_int {
        self.fd.0
    }
}

impl From<NonZeroU32> for Object {
    fn from(id: NonZeroU32) -> Self {
        Object { id }
    }
}

#[repr(u32)]
pub enum BpfCmd {
    MapCreate,
    MapLookupElem,
    MapUpdateElem,
    MapDeleteElem,
    MapGetNextKey,
    ProgLoad,
    ObjPin,
    ObjGet,
    ProgAttach,
    ProgDetach,
    ProgTestRun,
    ProgGetNextId,
    MapGetNextId,
    ProgGetFdById,
    MapGetFdById,
    ObjGetInfoByFd,
    ProgQuery,
    RawTracepointOpen,
    BtfLoad,
    BtfGetFdById,
    TaskFdQuery,
    MapLookupAndDeleteElem,
    MapFreeze,
    BtfGetNextId,
    MapLookupBatch,
    MapLookupAndDeleteBatch,
    MapUpdateBatch,
    MapDeleteBatch,
    LinkCreate,
    LinkUpdate,
    LinkGetFdById,
    LinkGetNextId,
    EnableStats,
    IterCreate,
    LinkDetach,
    ProgBindMap,
}

#[repr(transparent)]
#[derive(Default, Clone, Copy, PartialEq, Eq)]
pub struct OutAddr(pub u64);

#[repr(C)]
pub struct BpfOjbGetInfoByFd {
    pub fd: u32,
    pub info_len: u32,
    pub info: *mut u64,
}

#[repr(C, align(8))]
#[derive(Default, Clone, Copy)]
pub struct BpfProgInfo {
    pub type_: u32,
    pub id: u32,
    pub tag: [u8; 8],
    pub jited_prog_len: u32,
    pub xlated_prog_len: u32,
    pub jited_prog_insns: OutAddr,
    pub xlated_prog_insns: OutAddr,
    pub load_time: u64,
    pub created_by_uid: u32,
    pub nr_map_ids: u32,
    pub map_ids: OutAddr,
    pub name: [u8; 16],
    pub ifindex: u32,
    /// bitfield:1
    pub gpl_compatible: u32,
    pub netns_dev: u64,
    pub netns_ino: u64,
    pub nr_jited_ksyms: u32,
    pub nr_jited_func_lens: u32,
    pub jited_ksyms: OutAddr,
    pub jited_func_lens: OutAddr,
    pub btf_id: u32,
    pub func_info_rec_size: u32,
    pub func_info: u64,
    pub nr_func_info: u32,
    pub nr_line_info: u32,
    pub line_info: OutAddr,
    pub jited_line_info: OutAddr,
    pub nr_jited_line_info: u32,
    pub line_info_rec_size: u32,
    pub jited_line_info_rec_size: u32,
    pub nr_prog_tags: u32,
    pub prog_tags: OutAddr,
    pub run_time_ns: u64,
    pub run_cnt: u64,
    pub recursion_misses: u64,
    pub verified_insns: u32,
    pub attach_btf_obj_id: u32,
    pub attach_btf_id: u32,
}

/// Supply the temporary output pointers for a usable `BpfProgInfo`.
///
/// While the structure `BpfProgInfo` is valid on its own (just a bunch of numbers), the _use_ of
/// the structure as a bpf-syscall parameter depends on its pointer-like attributes pointing to
/// valid addresses. This struct initializes them in such a way that they are correct.
#[non_exhaustive]
#[derive(Default)]
pub struct BpfProgOut<'lt> {
    pub map_ids: Option<&'lt mut [u32]>,
}

unsafe impl bytemuck::Zeroable for BpfProgInfo {}
unsafe impl bytemuck::Pod for BpfProgInfo {}

#[repr(C, align(8))]
#[derive(Default, Clone, Copy)]
pub struct BpfMapInfo {
    pub type_: u32,
    pub id: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub map_flags: u32,
    pub name: [u8; 16],
    pub ifindex: u32,
    pub btf_vmlinux_value_type_id: u32,
    pub netns_dev: u64,
    pub netns_ino: u64,
    pub btf_id: u32,
    pub btf_key_type_id: u32,
    pub btf_value_type_id: u32,
    pub _pad: u32,
    pub map_extra: u64,
}

unsafe impl bytemuck::Zeroable for BpfMapInfo {}
unsafe impl bytemuck::Pod for BpfMapInfo {}

#[repr(C, align(8))]
#[derive(Default, Clone, Copy)]
struct BpfBtfInfo {
    pub btf: u64,
    pub btf_size: u32,
    pub id: u32,
    pub name: u64,
    pub name_len: u32,
    pub kernel_btf: u32,
}

unsafe impl bytemuck::Zeroable for BpfBtfInfo {}
unsafe impl bytemuck::Pod for BpfBtfInfo {}

impl BpfCmd {
    #[allow(non_upper_case_globals)]
    const BpfProgRun: Self = Self::ProgTestRun;
}
