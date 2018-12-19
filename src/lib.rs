#[macro_use]
extern crate log;

use std::convert::From;
use std::str::Utf8Error;

pub mod ch;
pub mod conn;
pub mod ctx;
pub mod settings;
#[allow(non_camel_case_types, non_upper_case_globals, dead_code)]
mod tls;
#[allow(non_camel_case_types)]
pub mod vtx;

#[derive(Debug)]
pub enum BeepError {
    TlsInitFailed,
    TlsConnectFailed(String),
    SaslInitFailed,
    SaslAuthFailed(String),
    ConnectionFailed(String),
    ChannelCreationFailed,
    ChannelSendFailed,
    StateError(String),
}

pub enum LogLevel {
    None,
    FirstLevel,
    SecondLevel,
}

impl From<Utf8Error> for BeepError {
    fn from(_: Utf8Error) -> BeepError {
        BeepError::StateError(String::from("UTF8 conversion failed"))
    }
}
