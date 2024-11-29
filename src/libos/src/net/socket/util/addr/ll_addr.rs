use crate::Domain;

use super::Addr;
use super::{CSockAddr, SockAddr};
use crate::prelude::*;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LinkLayerSocketAddr {
    pub sll_protocol: u16,
    pub sll_ifindex: i32,
    pub sll_hatype: u16,
    pub sll_pkttype: u8,
    pub sll_halen: u8,
    pub sll_addr: [u8; 8],
}

impl Addr for LinkLayerSocketAddr {
    fn domain() -> crate::Domain {
        Domain::PACKET
    }

    fn from_c_storage(
        c_addr: &sgx_trts::libc::sockaddr_storage,
        c_addr_len: usize,
    ) -> Result<Self> {
        if c_addr_len > std::mem::size_of::<libc::sockaddr_storage>() {
            return_errno!(EINVAL, "address length is too large");
        }

        if c_addr_len < std::mem::size_of::<libc::sockaddr_ll>() {
            return_errno!(EINVAL, "address length is too small");
        }
        // Safe to convert from sockaddr_storage to sockaddr_ll
        let c_addr = unsafe { std::mem::transmute(c_addr) };
        Self::from_c(c_addr)
    }

    fn to_c_storage(&self) -> (sgx_trts::libc::sockaddr_storage, usize) {
        let c_ll_addr = self.to_c();
        (c_ll_addr, std::mem::size_of::<libc::sockaddr_ll>()).to_c_storage()
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn is_default(&self) -> bool {
        let lladdr_any_init = Self::default();
        *self == lladdr_any_init
    }
}

impl LinkLayerSocketAddr {
    pub fn new(
        sll_protocol: u16,
        sll_ifindex: i32,
        sll_hatype: u16,
        sll_pkttype: u8,
        sll_halen: u8,
        sll_addr: [u8; 8],
    ) -> Self {
        Self {
            sll_protocol,
            sll_ifindex,
            sll_hatype,
            sll_pkttype,
            sll_halen,
            sll_addr,
        }
    }

    // only sll_protocol use big endian
    pub fn from_c(c_addr: &libc::sockaddr_ll) -> Result<Self> {
        if c_addr.sll_family != libc::AF_PACKET as libc::sa_family_t {
            return_errno!(EINVAL, "a packet address is expected")
        }
        Ok(Self {
            sll_protocol: u16::from_be(c_addr.sll_protocol),
            sll_ifindex: c_addr.sll_ifindex,
            sll_hatype: c_addr.sll_hatype,
            sll_pkttype: c_addr.sll_pkttype,
            sll_halen: c_addr.sll_halen,
            sll_addr: c_addr.sll_addr,
        })
    }

    pub fn to_c(&self) -> libc::sockaddr_ll {
        libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as _,
            sll_protocol: self.sll_protocol.to_be(),
            sll_ifindex: self.sll_ifindex,
            sll_hatype: self.sll_hatype,
            sll_pkttype: self.sll_pkttype,
            sll_halen: self.sll_halen,
            sll_addr: self.sll_addr,
        }
    }

    pub fn to_raw(&self) -> SockAddr {
        let (storage, len) = self.to_c_storage();
        SockAddr::from_c_storage(&storage, len)
    }

    pub fn sll_protocol(&self) -> u16 {
        self.sll_protocol
    }

    pub fn sll_ifindex(&self) -> i32 {
        self.sll_ifindex
    }

    pub fn sll_hatype(&self) -> u16 {
        self.sll_hatype
    }

    pub fn sll_pkttype(&self) -> u8 {
        self.sll_pkttype
    }

    pub fn sll_halen(&self) -> u8 {
        self.sll_halen
    }

    pub fn sll_addr(&self) -> &[u8; 8] {
        &self.sll_addr
    }

    pub fn set_sll_protocol(&mut self, new_sll_protocol: u16) {
        self.sll_protocol = new_sll_protocol
    }

    pub fn set_sll_ifindex(&mut self, new_sll_ifindex: i32) {
        self.sll_ifindex = new_sll_ifindex
    }

    pub fn set_sll_hatype(&mut self, new_sll_hatype: u16) {
        self.sll_hatype = new_sll_hatype
    }

    pub fn set_sll_pkttype(&mut self, new_sll_pkttype: u8) {
        self.sll_pkttype = new_sll_pkttype
    }

    pub fn set_sll_halen(&mut self, new_sll_halen: u8) {
        self.sll_halen = new_sll_halen
    }

    pub fn set_sll_addr(&mut self, new_sll_addr: [u8; 8]) {
        self.sll_addr = new_sll_addr
    }
}

impl Default for LinkLayerSocketAddr {
    fn default() -> Self {
        Self::new(0, 0, 0, 0, 0, [0; 8])
    }
}
