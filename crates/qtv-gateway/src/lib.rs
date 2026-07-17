//! The Quantova RPC gateway.
//!
//! Six methods over plain HTTP with our own JSON, node info, get account, submit
//! transaction, get transaction, get block, and head. The gateway holds no chain
//! state. It parses a request in its own thread and hands it to the node over a
//! channel, and the node, which stays the single owner of its state, handles the
//! request and replies. That channel is the whole boundary between the two, so the
//! gateway can later run in its own process by carrying the request and the reply over
//! a socket instead, and nothing about the node changes. Nothing here borrows another
//! chain's method names or wire shape.

#![forbid(unsafe_code)]

pub mod json;
pub mod service;

mod http;

use std::sync::mpsc::Sender;

pub use http::serve;
pub use json::Json;
pub use service::{
    build_request, handle, BlockSelector, ClientError, NodeContext, Request,
};

/// A built request handed to the node with the channel to reply on. The gateway sends
/// this to the round loop, which owns the node, handles it, and replies. The node is
/// never shared behind a lock, only asked, so a shared lock cannot accumulate
/// assumptions and the split to a separate process stays a socket swap.
pub struct GatewayCall {
    pub request: Request,
    pub reply: Sender<Result<Json, ClientError>>,
}
