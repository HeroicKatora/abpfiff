use crate::sys::LibBpfErrno;

#[repr(u16)]
#[allow(non_camel_case_types)]
pub enum IflaType {
    IFLA_UNSPEC,
    IFLA_ADDRESS,
    IFLA_BROADCAST,
    IFLA_IFNAME,
    IFLA_MTU,
    IFLA_LINK,
    IFLA_QDISC,
    IFLA_STATS,
    IFLA_COST,
    IFLA_PRIORITY,
    IFLA_MASTER,
    IFLA_WIRELESS, /* Wireless Extension event - see wireless.h */
    IFLA_PROTINFO, /* Protocol specific information for a link */
    IFLA_TXQLEN,
    IFLA_MAP,
    IFLA_WEIGHT,
    IFLA_OPERSTATE,
    IFLA_LINKMODE,
    IFLA_LINKINFO,
    IFLA_NET_NS_PID,
    IFLA_IFALIAS,
    IFLA_NUM_VF, /* Number of VFs if device is SR-IOV PF */
    IFLA_VFINFO_LIST,
    IFLA_STATS64,
    IFLA_VF_PORTS,
    IFLA_PORT_SELF,
    IFLA_AF_SPEC,
    IFLA_GROUP, /* Group the device belongs to */
    IFLA_NET_NS_FD,
    IFLA_EXT_MASK,    /* Extended info mask, VFs, etc */
    IFLA_PROMISCUITY, /* Promiscuity count: > 0 means acts PROMISC */
    IFLA_NUM_TX_QUEUES,
    IFLA_NUM_RX_QUEUES,
    IFLA_CARRIER,
    IFLA_PHYS_PORT_ID,
    IFLA_CARRIER_CHANGES,
    IFLA_PHYS_SWITCH_ID,
    IFLA_LINK_NETNSID,
    IFLA_PHYS_PORT_NAME,
    IFLA_PROTO_DOWN,
    IFLA_GSO_MAX_SEGS,
    IFLA_GSO_MAX_SIZE,
    IFLA_PAD,
    IFLA_XDP,
    IFLA_EVENT,
    IFLA_NEW_NETNSID,
    // IFLA_IF_NETNSID, /* has a new new alias, below */
    IFLA_TARGET_NETNSID,
    IFLA_CARRIER_UP_COUNT,
    IFLA_CARRIER_DOWN_COUNT,
    IFLA_NEW_IFINDEX,
    IFLA_MIN_MTU,
    IFLA_MAX_MTU,
    IFLA_PROP_LIST,
    IFLA_ALT_IFNAME, /* Alternative ifname */
    IFLA_PERM_ADDRESS,
    IFLA_PROTO_DOWN_REASON,

    /* device (sysfs) name as parent, used instead
     * of IFLA_LINK where there's no parent netdev
     */
    IFLA_PARENT_DEV_NAME,
    IFLA_PARENT_DEV_BUS_NAME,
    IFLA_GRO_MAX_SIZE,
    IFLA_TSO_MAX_SIZE,
    IFLA_TSO_MAX_SEGS,
    __IFLA_MAX,
}

pub const IFLA_MAX: usize = IflaType::__IFLA_MAX as usize;

#[repr(u16)]
#[allow(non_camel_case_types)]
pub enum IflaXdp {
    IFLA_XDP_UNSPEC,
    IFLA_XDP_FD,
    IFLA_XDP_ATTACHED,
    IFLA_XDP_FLAGS,
    IFLA_XDP_PROG_ID,
    IFLA_XDP_DRV_PROG_ID,
    IFLA_XDP_SKB_PROG_ID,
    IFLA_XDP_HW_PROG_ID,
    IFLA_XDP_EXPECTED_FD,
    __IFLA_XDP_MAX,
}

pub const IFLA_XDP_MAX: usize = IflaXdp::__IFLA_XDP_MAX as usize;

#[derive(Clone, Copy, Default, Debug)]
pub(crate) struct Attr<'a> {
    pub(crate) data: Option<&'a [u8]>,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct NlAttr {
    len: u16,
    type_: u16,
}

unsafe impl bytemuck::Zeroable for NlAttr {}
unsafe impl bytemuck::Pod for NlAttr {}

pub(crate) fn parse<'d>(into: &mut [Attr<'d>], mut data: &'d [u8]) -> Result<(), LibBpfErrno> {
    loop {
        let nla = match data.get(..core::mem::size_of::<NlAttr>()) {
            // FIXME: huh, partial data is treated as okay.
            None => break,
            Some(nla) => nla,
        };

        let nl_attr: &NlAttr = match bytemuck::try_from_bytes(nla) {
            Ok(attr) => attr,
            Err(_) => break,
        };

        let len = usize::from(nl_attr.len);

        if !(core::mem::size_of::<NlAttr>() < len) {
            return Err(LibBpfErrno::LIBBPF_ERRNO__NLPARSE);
        }

        let pad_len = (len + 3) & !3;
        let nla_data;

        match data.get(pad_len..) {
            None => return Err(LibBpfErrno::LIBBPF_ERRNO__NLPARSE),
            Some(tail) => {
                nla_data = &data[core::mem::size_of::<NlAttr>()..len];
                data = tail;
            }
        }

        if let Some(slot) = into.get_mut(usize::from(nl_attr.type_)) {
            *slot = Attr {
                data: Some(nla_data),
            };
        }
    }

    Ok(())
}

impl Attr<'_> {
    pub fn is_set(&self) -> bool {
        self.data.is_some()
    }

    pub fn getattr_u8(&self) -> Result<u8, LibBpfErrno> {
        if let Some([val]) = self.data {
            Ok(*val)
        } else {
            Err(LibBpfErrno::LIBBPF_ERRNO__NLPARSE)
        }
    }

    pub fn getattr_u32(&self) -> Result<u32, LibBpfErrno> {
        if let Some(&[a, b, c, d]) = self.data {
            Ok(u32::from_ne_bytes([a, b, c, d]))
        } else {
            Err(LibBpfErrno::LIBBPF_ERRNO__NLPARSE)
        }
    }
}
