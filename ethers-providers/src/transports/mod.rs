mod common;
pub use common::Authorization;

mod http;
pub use self::http::{ClientError as HttpClientError, Provider as Http};

#[cfg(all(feature = "ipc", any(unix, windows)))]
mod ipc;
#[cfg(all(feature = "ipc", any(unix, windows)))]
pub use ipc::{Ipc, IpcError};

#[cfg(feature = "ws")]
mod ws;
#[cfg(feature = "ws")]
pub use ws::{ClientError as WsClientError, Ws};

mod quorum;
pub use quorum::{JsonRpcClientWrapper, Quorum, QuorumError, QuorumProvider, WeightedProvider};

mod rw;
pub use rw::{RwClient, RwClientError};

mod retry;
pub use retry::*;

#[cfg(all(feature = "eip1193"))]
mod eip1193;
#[cfg(all(feature = "eip1193"))]
pub use eip1193::Eip1193;

mod mock;
pub use mock::{MockError, MockProvider};
