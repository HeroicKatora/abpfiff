//! Interact with bpf(2).
use crate::{
    sys::{ArcTable, LibBpfErrno},
    Errno, MapFd, Object, ProgramFd,
};
use core::{ffi::CStr, num::NonZeroU32};

mod sealed {
    /// A dyn-compatible version of `bytemuck::AnyBitPattern`.
    /// # Safety
    ///
    /// Same as `bytemuck::AnyBitPattern`.
    pub unsafe trait OutputAnyBitPattern {}

    /// Safety: by definition.
    unsafe impl<T: bytemuck::AnyBitPattern> OutputAnyBitPattern for T {}

    /// How we use this.
    fn __assert_feasible_output_any_bit_pattern(_: &dyn OutputAnyBitPattern) {}

    /// A dyn-compatible version of `bytemuck::Pod`.
    /// # Safety
    ///
    /// Same as `bytemuck::Pod`.
    pub unsafe trait ParameterPod {}

    /// Safety: by definition.
    unsafe impl<T: bytemuck::Pod> ParameterPod for T {}

    /// How we use this.
    fn __assert_feasible_parameter_pod(_: &dyn ParameterPod) {}
}

impl ArcTable {
    pub fn get_progfd_by_id(&self, id: Object) -> Result<ProgramFd, Errno> {
        let fd = self.raw_fd_by_id(id, BpfCmd::ProgGetFdById)?;
        let fd = self.wrap_fd(fd);
        Ok(ProgramFd { fd })
    }

    pub fn get_mapfd_by_id(&self, id: Object) -> Result<MapFd, Errno> {
        let fd = self.raw_fd_by_id(id, BpfCmd::MapGetFdById)?;
        let fd = self.wrap_fd(fd);
        Ok(MapFd {
            fd,
            key_size_access_requirement: None,
            val_size_access_requirement: None,
        })
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
            info.map_ids = ValAddr(map_ids.as_mut_ptr() as u64);
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

    /// Retrieve the info of this map; and remember the safety relevant details in `MapFd`.
    pub fn get_mapfd_info_mut(
        &self,
        prog: &mut MapFd,
        info: &mut BpfMapInfo,
    ) -> Result<usize, Errno> {
        let data = bytemuck::bytes_of_mut(info);
        let data = bytemuck::cast_slice_mut(data);
        let size = unsafe { self.raw_info_by_fd(prog.as_raw_fd(), data) }?;
        prog.key_size_access_requirement = Some(info.key_size);
        prog.val_size_access_requirement = Some(info.value_size);
        Ok(size)
    }

    pub fn get_mapfd_info(&self, prog: &MapFd, info: &mut BpfMapInfo) -> Result<usize, Errno> {
        let data = bytemuck::bytes_of_mut(info);
        let data = bytemuck::cast_slice_mut(data);
        unsafe { self.raw_info_by_fd(prog.as_raw_fd(), data) }
    }

    pub fn get_progfd_pinned(&self, path: &CStr) -> Result<ProgramFd, Errno> {
        let fd = self.raw_obj_fd_get(path)?;
        let fd = self.wrap_fd(fd);
        Ok(ProgramFd { fd })
    }

    /// Fetch a map entry.
    ///
    /// The map info must have been retrieved with `get_mapfd_info_mut` previously since the map
    /// will validate the parameter references passed in. Returns the key and value size that have
    /// been used in actuality.
    ///
    /// This is a generic shim to capture the allowed parameters `V` precisely. The kernel _may_
    /// write to `val`'s bytes on success which will initialize them. The alternatives:
    ///
    /// * `&mut [u8]` is too strong a requirement, as the bytes don't need to be initialized.
    /// * `&mut dyn _` is not possible as the trait is not object safe (`Copy`).
    pub fn lookup_map_element(
        &self,
        map: &MapFd,
        key: &dyn sealed::ParameterPod,
        val: &mut dyn sealed::OutputAnyBitPattern,
    ) -> Result<(u32, u32), Errno> {
        let key_sz = match map.key_size_access_requirement {
            Some(sz) if u32::try_from(core::mem::size_of_val(key)).unwrap_or(u32::MAX) >= sz => sz,
            _ => return Err(self.mk_errno(libc::EINVAL)),
        };

        let val_sz = match map.val_size_access_requirement {
            Some(sz) if u32::try_from(core::mem::size_of_val(val)).unwrap_or(u32::MAX) >= sz => sz,
            _ => return Err(self.mk_errno(libc::EINVAL)),
        };

        let mut attr = BpfMapGetElem {
            map_fd: map.fd.0 as u32,
            key: ValAddr(key as *const _ as *const u8 as u64),
            value: ValAddr(val as *mut _ as *mut u8 as u64),
            ..bytemuck::Zeroable::zeroed()
        };

        let attr_sz = core::mem::size_of_val(&attr) as u32;
        if unsafe {
            (self.bpf)(
                BpfCmd::MapLookupElem as i64,
                (&mut attr) as *mut _ as *mut libc::c_void,
                attr_sz,
            )
        } < 0
        {
            return Err(self.errno());
        } else {
            Ok((key_sz, val_sz))
        }
    }

    pub unsafe fn raw_info_by_fd(&self, fd: libc::c_int, info: &mut [u8]) -> Result<usize, Errno> {
        let info_len = u32::try_from(info.len()).unwrap_or(u32::MAX);

        let mut attr = BpfOjbGetInfoByFd {
            fd: fd as u32,
            info_len,
            info: ValAddr(info.as_mut_ptr() as u64),
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

    pub(crate) fn raw_fd_by_id(&self, id: Object, cmd: BpfCmd) -> Result<libc::c_int, Errno> {
        let mut attr = BpfGetId {
            id: id.id.get(),
            next_id: 0,
            open_flags: 0,
        };

        let attr_sz = core::mem::size_of_val(&attr) as u32;

        let fd = unsafe {
            (self.bpf)(
                cmd as libc::c_long,
                (&mut attr) as *mut _ as *mut libc::c_void,
                attr_sz,
            )
        };

        if fd < 0 {
            return Err(self.errno());
        }

        match libc::c_int::try_from(fd) {
            Ok(fd) => Ok(fd),
            Err(_) => Err(self.bpf_err(LibBpfErrno::LIBBPF_ERRNO__INTERNAL)),
        }
    }

    pub(crate) fn raw_obj_fd_get(&self, path: &CStr) -> Result<libc::c_int, Errno> {
        let mut attr = BpfObjByPath {
            pathname: ValAddr(path.as_ptr() as u64),
            bpf_fd: 0,
            file_flags: 0,
        };

        let attr_sz = core::mem::size_of_val(&attr) as u32;
        let fd = unsafe {
            (self.bpf)(
                BpfCmd::ObjGet as libc::c_long,
                (&mut attr) as *mut _ as *mut libc::c_void,
                attr_sz,
            )
        };

        if fd < 0 {
            return Err(self.errno());
        }

        match libc::c_int::try_from(fd) {
            Ok(fd) => Ok(fd),
            Err(_) => Err(self.bpf_err(LibBpfErrno::LIBBPF_ERRNO__INTERNAL)),
        }
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

#[repr(align(8))]
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValAddr(pub u64);

#[repr(C)]
pub struct BpfOjbGetInfoByFd {
    pub fd: u32,
    pub info_len: u32,
    pub info: ValAddr,
}

#[repr(C, align(8))]
#[derive(Default, Debug, Clone, Copy)]
pub struct BpfProgInfo {
    pub type_: u32,
    pub id: u32,
    pub tag: [u8; 8],
    pub jited_prog_len: u32,
    pub xlated_prog_len: u32,
    pub jited_prog_insns: ValAddr,
    pub xlated_prog_insns: ValAddr,
    pub load_time: u64,
    pub created_by_uid: u32,
    pub nr_map_ids: u32,
    pub map_ids: ValAddr,
    pub name: [u8; 16],
    pub ifindex: u32,
    /// bitfield:1
    pub gpl_compatible: u32,
    pub netns_dev: u64,
    pub netns_ino: u64,
    pub nr_jited_ksyms: u32,
    pub nr_jited_func_lens: u32,
    pub jited_ksyms: ValAddr,
    pub jited_func_lens: ValAddr,
    pub btf_id: u32,
    pub func_info_rec_size: u32,
    pub func_info: u64,
    pub nr_func_info: u32,
    pub nr_line_info: u32,
    pub line_info: ValAddr,
    pub jited_line_info: ValAddr,
    pub nr_jited_line_info: u32,
    pub line_info_rec_size: u32,
    pub jited_line_info_rec_size: u32,
    pub nr_prog_tags: u32,
    pub prog_tags: ValAddr,
    pub run_time_ns: u64,
    pub run_cnt: u64,
    pub recursion_misses: u64,
    pub verified_insns: u32,
    pub attach_btf_obj_id: u32,
    pub attach_btf_id: u32,
    pub _pad_to_align_8: u32,
}

unsafe impl bytemuck::Zeroable for BpfProgInfo {}
unsafe impl bytemuck::Pod for BpfProgInfo {}

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

#[repr(C, align(8))]
#[derive(Default, Debug, Clone, Copy)]
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
#[derive(Default, Debug, Clone, Copy)]
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

/// Get state for an object by ID. For instance, get a file descriptor for an object.
/// The raw argument struct of `bpf(BPF_*_GET_*_ID, ..)`
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BpfGetId {
    #[doc(
        alias = "prog_id",
        alias = "start_id",
        alias = "map_id",
        alias = "btf_id",
        alias = "link_id"
    )]
    pub id: u32,
    pub next_id: u32,
    pub open_flags: u32,
}

unsafe impl bytemuck::Zeroable for BpfGetId {}
unsafe impl bytemuck::Pod for BpfGetId {}

/// Modify some object by path.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BpfObjByPath {
    pub pathname: ValAddr,
    pub bpf_fd: u32,
    pub file_flags: u32,
}

unsafe impl bytemuck::Zeroable for BpfObjByPath {}
unsafe impl bytemuck::Pod for BpfObjByPath {}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy)]
pub struct BpfMapGetElem {
    pub map_fd: u32,
    pub _pad: u32,
    pub key: ValAddr,
    #[doc(alias = "next_key")]
    pub value: ValAddr,
    pub flags: u64,
}

unsafe impl bytemuck::Zeroable for BpfMapGetElem {}
unsafe impl bytemuck::Pod for BpfMapGetElem {}

impl BpfCmd {
    #[allow(non_upper_case_globals)]
    const BpfProgRun: Self = Self::ProgTestRun;
}
