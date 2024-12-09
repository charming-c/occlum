use num_enum::{IntoPrimitive, TryFromPrimitive};

/* Standard well-defined IP protocols.  */
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum SocketProtocol {
    IPProtocol(IPProtocol),
    NetlinkProtocol(NetlinkProtocol),
}

impl SocketProtocol {
    pub fn to_i32(self) -> Option<i32> {
        match self {
            SocketProtocol::IPProtocol(ip) => Some(ip.into()),
            SocketProtocol::NetlinkProtocol(netlink) => Some(netlink.into()),
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, IntoPrimitive, TryFromPrimitive)]
#[repr(i32)]
pub enum IPProtocol {
    IPPROTO_IP = 0,        /* Dummy protocol for TCP.  */
    IPPROTO_ICMP = 1,      /* Internet Control Message Protocol.  */
    IPPROTO_IGMP = 2,      /* Internet Group Management Protocol. */
    IPPROTO_IPIP = 4,      /* IPIP tunnels (older KA9Q tunnels use 94).  */
    IPPROTO_TCP = 6,       /* Transmission Control Protocol.  */
    IPPROTO_EGP = 8,       /* Exterior Gateway Protocol.  */
    IPPROTO_PUP = 12,      /* PUP protocol.  */
    IPPROTO_UDP = 17,      /* User Datagram Protocol.  */
    IPPROTO_IDP = 22,      /* XNS IDP protocol.  */
    IPPROTO_TP = 29,       /* SO Transport Protocol Class 4.  */
    IPPROTO_DCCP = 33,     /* Datagram Congestion Control Protocol.  */
    IPPROTO_IPV6 = 41,     /* IPv6 header.  */
    IPPROTO_RSVP = 46,     /* Reservation Protocol.  */
    IPPROTO_GRE = 47,      /* General Routing Encapsulation.  */
    IPPROTO_ESP = 50,      /* encapsulating security payload.  */
    IPPROTO_AH = 51,       /* authentication header.  */
    IPPROTO_MTP = 92,      /* Multicast Transport Protocol.  */
    IPPROTO_BEETPH = 94,   /* IP option pseudo header for BEET.  */
    IPPROTO_ENCAP = 98,    /* Encapsulation Header.  */
    IPPROTO_PIM = 103,     /* Protocol Independent Multicast.  */
    IPPROTO_COMP = 108,    /* Compression Header Protocol.  */
    IPPROTO_SCTP = 132,    /* Stream Control Transmission Protocol.  */
    IPPROTO_UDPLITE = 136, /* UDP-Lite protocol.  */
    IPPROTO_MPLS = 137,    /* MPLS in IP.  */
    IPPROTO_RAW = 255,     /* Raw IP packets.  */
    IPPROTO_MAX,
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, IntoPrimitive, TryFromPrimitive)]
#[repr(i32)]
pub enum NetlinkProtocol {
    NETLINK_ROUTE = 0,     /* Routing/device hook.  */
    NETLINK_USERSOCK = 2,  /* Reserved for user mode socket protocols.  */
    NETLINK_FIREWALL = 3,  /* Unused number, formerly ip_queue.  */
    NETLINK_SOCK_DIAG = 4, /* socket monitoring.  */
    NETLINK_NFLOG = 5,     /* netfilter/iptables ULOG.  */
    NETLINK_XFRM = 6,      /* ipsec.  */
    NETLINK_SELINUX = 7,   /* SELinux event notifications.  */
    NETLINK_ISCSI = 8,     /* Open-iSCSI.  */
    NETLINK_AUDIT = 9,     /* auditing.  */
    NETLINK_FIB_LOOKUP = 10,
    NETLINK_CONNECTOR = 11,
    NETLINK_NETFILTER = 12, /* netfilter subsystem.  */
    NETLINK_IP6_FW = 13,
    NETLINK_DNRTMSG = 14,        /* DECnet routing messages.  */
    NETLINK_KOBJECT_UEVENT = 15, /* Kernel messages to userspace.  */
    NETLINK_GENERIC = 16,
    NETLINK_SCSITRANSPORT = 18, /* SCSI Transports.  */
    NETLINK_ECRYPTFS = 19,
    NETLINK_CRYPTO = 21, /* Crypto layer.  */
}
