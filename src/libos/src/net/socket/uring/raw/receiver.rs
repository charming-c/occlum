use crate::fs::IoEvents as Events;
use crate::prelude::*;
use crate::util::sync::MutexGuard;
use crate::{
    net::socket::uring::{common::Common, runtime::Runtime},
    Addr,
};

pub struct Receiver<A: Addr + 'static, R: Runtime> {
    common: Arc<Common<A, R>>,
    inner: Mutex<Inner>,
}

impl<A: Addr, R: Runtime> Receiver<A, R> {
    pub fn new(common: Arc<Common<A, R>>) -> Arc<Self> {
        common.pollee().add_events(Events::OUT);
        let inner = Mutex::new(Inner::new());
        Arc::new(Self { common, inner })
    }
}

struct Inner {}

impl Inner {
    fn new() -> Self {
        Inner {}
    }
}
