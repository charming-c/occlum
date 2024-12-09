use super::*;
use crate::{
    net::socket::uring::{
        common::{self, Common},
        raw::sender::Sender,
        runtime::Runtime,
    },
    Addr, RwLock,
};

pub struct RawProto<A: Addr + 'static, R: Runtime> {
    common: Arc<Common<A, R>>,
    sender: Arc<Sender<A, R>>,
}

impl<A: Addr, R: Runtime> RawProto<A, R> {
    pub fn new(common: Arc<Common<A, R>>) -> Arc<Self> {
        let sender = Sender::new(common.clone());
        Arc::new(Self { common, sender })
    }
}
