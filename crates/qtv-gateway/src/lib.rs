// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

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

pub struct GatewayCall {
    pub request: Request,
    pub reply: Sender<Result<Json, ClientError>>,
}
