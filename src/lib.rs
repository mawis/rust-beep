#[macro_use]
extern crate log;
extern crate libc;

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
}

pub enum LogLevel {
    None,
    FirstLevel,
    SecondLevel,
}
