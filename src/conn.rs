use super::*;

use std::ffi::{CStr, CString};
use std::os::raw;
use std::ptr;

pub struct Connection {
    conn: *mut vtx::VortexConnection,
}

impl<'a> Connection {
    pub fn for_raw(
        conn: *mut vtx::VortexConnection,
    ) -> Connection {
        if conn.is_null() {
            panic!("VortexConnection is null pointer.");
        }

        Connection { conn }
    }

    pub fn authenticate(&self, id: settings::Sasl) -> Result<(), BeepError> {
        unsafe {
            let mut status: vtx::VortexStatus = 0;
            let mut status_message: *mut raw::c_char = ptr::null_mut();
            let sasl_auth_id = CString::new(id.auth_id).unwrap();
            let sasl_password = CString::new(id.password).unwrap();
            vtx::vortex_sasl_set_propertie(
                self.conn,
                vtx::SASL_AUTH_ID,
                sasl_auth_id.as_ptr() as *mut i8,
                None,
            );
            vtx::vortex_sasl_set_propertie(
                self.conn,
                vtx::SASL_PASSWORD,
                sasl_password.as_ptr() as *mut i8,
                None,
            );
            vtx::vortex_sasl_start_auth_sync(
                self.conn,
                vtx::SASL_PLAIN.as_ptr() as *const i8,
                &mut status,
                &mut status_message,
            );

            if vtx::vortex_sasl_is_authenticated(self.conn) != 0 {
                Ok(())
            } else {
                let msg = format!(
                    "SASL authentication failed: \
                             status={}, message={:?}",
                    status,
                    CStr::from_ptr(status_message)
                );
                Err(BeepError::SaslAuthFailed(msg))
            }
        }
    }

    pub fn get_channel(&self, channel_no: u32) -> Option<ch::Channel> {
        unsafe {
            let ch = vtx::vortex_connection_get_channel(
                self.conn,
                channel_no as raw::c_int);
            if ch.is_null() {
                None
            } else {
                Some(ch::Channel::for_raw(self, ch))
            }
        }
    }

    pub fn channel_new(
        &self,
        profile: &str,
    ) -> Result<ch::Channel, BeepError> {
        let channel_profile = CString::new(profile).unwrap();
        unsafe {
            let channel = vtx::vortex_channel_new(
                self.conn,
                0,
                channel_profile.as_ptr(),
                None,
                ptr::null_mut(),
                None,
                ptr::null_mut(),
                None,
                ptr::null_mut(),
            );

            if channel.is_null() {
                Err(BeepError::ChannelCreationFailed)
            } else {
                vtx::vortex_channel_create_wait_reply();
                Ok(ch::Channel::for_raw(self, channel))
            }
        }
    }
}

unsafe impl Send for Connection{}
