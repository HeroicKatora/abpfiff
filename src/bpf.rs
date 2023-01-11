//! Interact with bpf(2).

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

impl BpfCmd {
    #[allow(non_upper_case_globals)]
    const BpfProgRun: Self = Self::ProgTestRun;
}
