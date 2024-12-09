mod ip;
mod packet;
mod receiver;
mod sender;

use self::receiver::Receiver;
use self::sender::Sender;
use crate::prelude::*;

const MAX_BUF_SIZE: usize = 64 * 1024;
const OPTMEM_MAX: usize = 64 * 1024;
