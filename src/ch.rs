use super::*;

use std::os::raw;
use std::ptr;

pub struct Channel {
    channel: *mut vtx::VortexChannel,
}

impl<'a> Channel {
    pub fn for_raw(
        _conn: &'a conn::Connection,
        channel: *mut vtx::VortexChannel,
    ) -> Channel {
        Channel { channel }
    }

    pub fn send_msg(&self, message: String) -> Result<(), BeepError> {
        let message = message.as_bytes();
        unsafe {
            if vtx::vortex_channel_send_msg(
                self.channel,
                message.as_ptr() as *const raw::c_void,
                message.len(),
                ptr::null_mut(),
            ) == 0
            {
                Err(BeepError::ChannelSendFailed)
            } else {
                Ok(())
            }
        }
    }
}
