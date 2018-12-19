use super::*;

use std::os::raw;
use std::ptr;

pub struct Channel {
    channel: *mut vtx::VortexChannel,
}

impl<'a> Channel {
    pub fn for_raw(
        channel: *mut vtx::VortexChannel,
    ) -> Channel {
        Channel { channel }
    }

    pub fn send_msg(&self, message: String) -> Result<(), BeepError> {
        self.send_bytes(message.as_bytes())
    }

    pub fn send_bytes(&self, message: &[u8]) -> Result<(), BeepError> {
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
