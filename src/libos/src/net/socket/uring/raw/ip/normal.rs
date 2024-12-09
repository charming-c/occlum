use core::clone;

use super::*;
use crate::{
    net::socket::uring::{
        common::Common,
        raw::{receiver::Receiver, sender::Sender},
        runtime::Runtime,
    },
    Addr,
};

pub struct NormalProto<A: Addr + 'static, R: Runtime> {
    common: Arc<Common<A, R>>,
    sender: Arc<Sender<A, R>>,
    receiver: Arc<Receiver<A, R>>,
}

impl<A: Addr, R: Runtime> NormalProto<A, R> {
    pub fn new(common: Arc<Common<A, R>>) -> Arc<Self> {
        let sender = Sender::new(common.clone());
        let receiver = Receiver::new(common.clone());
        Arc::new(Self {
            common,
            sender,
            receiver,
        })
    }
}
