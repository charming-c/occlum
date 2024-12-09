mod normal;
mod raw;

use super::*;
use crate::{
    net::socket::{
        uring::{common::Common, runtime::Runtime},
        IPProtocol, SocketProtocol,
    },
    Addr,
};
use normal::NormalProto;
use raw::RawProto;

pub struct IpPacket<A: Addr + 'static, R: Runtime> {
    proto: ProtocolType<A, R>,
    state: RwLock<State>,
    common: Arc<Common<A, R>>,
}

impl<A: Addr, R: Runtime> IpPacket<A, R> {
    pub fn new(nonblocking: bool, proto: SocketProtocol) -> Result<Self> {
        let common = Arc::new(Common::new(SocketType::RAW, nonblocking, proto.to_i32())?);
        let state = RwLock::new(State::new());
        let proto = if proto == SocketProtocol::IPProtocol(IPProtocol::IPPROTO_RAW) {
            ProtocolType::RawProto(RawProto::new(common.clone()))
        } else {
            ProtocolType::NormalProto(NormalProto::new(common.clone()))
        };
        Ok(Self {
            common,
            state,
            proto,
        })
    }

    pub fn domain(&self) -> Domain {
        A::domain()
    }

    pub fn host_fd(&self) -> FileDesc {
        self.common.host_fd()
    }

    pub fn status_flags(&self) -> StatusFlags {
        // Only support O_NONBLOCK
        if self.common.nonblocking() {
            StatusFlags::O_NONBLOCK
        } else {
            StatusFlags::empty()
        }
    }

    pub fn set_status_flags(&self, new_flags: StatusFlags) -> Result<()> {
        // Only support O_NONBLOCK
        let nonblocking = new_flags.is_nonblocking();
        self.common.set_nonblocking(nonblocking);
        Ok(())
    }

    pub fn bind(&self, addr: &A) -> Result<()> {
        let mut state = self.state.write().unwrap();
        if state.is_bound() {
            return_errno!(EINVAL, "The socket is already bound to an address");
        }

        do_bind(self.host_fd(), addr)?;

        self.common.set_addr(addr);
        state.mark_explicit_bind();

        Ok(())
    }

    pub fn connect(&self, peer_addr: Option<&A>) -> Result<()> {
        let mut state = self.state.write().unwrap();

        // if previous peer.is_default() and peer_addr.is_none()
        // is unspec, so the situation exists that both
        // !state.is_connected() and peer_addr.is_none() are true.

        if let Some(peer) = peer_addr {
            do_connect(self.host_fd(), Some(peer))?;

            self.receiver.reset_shutdown();
            self.sender.reset_shutdown();
            self.common.set_peer_addr(peer);

            if peer.is_default() {
                state.mark_disconnected();
            } else {
                state.mark_connected();
            }
            if !state.is_bound() {
                state.mark_implicit_bind();
                // Start async recv after explicit binding or implicit binding
                self.receiver.initiate_async_recv();
            }

        // TODO: update binding address in some cases
        // For a ipv4 socket bound to 0.0.0.0 (INADDR_ANY), if you do connection
        // to 127.0.0.1 (Local IP address), the IP address of the socket will
        // change to 127.0.0.1 too. And if connect to non-local IP address, linux
        // will assign a address to the socket.
        // In both cases, we should update the binding address that we stored.
        } else {
            do_connect::<A>(self.host_fd(), None)?;

            self.common.reset_peer_addr();
            state.mark_disconnected();

            // TODO: clear binding in some cases.
            // Disconnect will effect the binding address. In Linux, for socket that
            // explicit bound to local IP address, disconnect will clear the binding address,
            // but leave the port intact. For socket with implicit bound, disconnect will
            // clear both the address and port.
        }
        Ok(())
    }
}

enum ProtocolType<A: Addr + 'static, R: Runtime> {
    RawProto(Arc<RawProto<A, R>>),
    NormalProto(Arc<NormalProto<A, R>>),
}

struct State {
    bind_state: BindState,
    is_connected: bool,
}

impl State {
    pub fn new() -> Self {
        Self {
            bind_state: BindState::Unbound,
            is_connected: false,
        }
    }

    pub fn new_connected() -> Self {
        Self {
            bind_state: BindState::Unbound,
            is_connected: true,
        }
    }

    pub fn is_bound(&self) -> bool {
        self.bind_state.is_bound()
    }

    #[allow(dead_code)]
    pub fn is_explicit_bound(&self) -> bool {
        self.bind_state.is_explicit_bound()
    }

    #[allow(dead_code)]
    pub fn is_implicit_bound(&self) -> bool {
        self.bind_state.is_implicit_bound()
    }

    pub fn is_connected(&self) -> bool {
        self.is_connected
    }

    pub fn mark_explicit_bind(&mut self) {
        self.bind_state = BindState::ExplicitBound;
    }

    pub fn mark_implicit_bind(&mut self) {
        self.bind_state = BindState::ImplicitBound;
    }

    pub fn mark_connected(&mut self) {
        self.is_connected = true;
    }

    pub fn mark_disconnected(&mut self) {
        self.is_connected = false;
    }
}

#[derive(Debug)]
enum BindState {
    Unbound,
    ExplicitBound,
    ImplicitBound,
}

impl BindState {
    pub fn is_bound(&self) -> bool {
        match self {
            Self::Unbound => false,
            _ => true,
        }
    }

    #[allow(dead_code)]
    pub fn is_explicit_bound(&self) -> bool {
        match self {
            Self::ExplicitBound => true,
            _ => false,
        }
    }

    #[allow(dead_code)]
    pub fn is_implicit_bound(&self) -> bool {
        match self {
            Self::ImplicitBound => true,
            _ => false,
        }
    }
}
