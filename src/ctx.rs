use super::*;

use std::ffi::{CStr, CString};
use std::mem;
use std::os::raw;
use std::ptr;
use std::slice;

pub struct Context {
    ctx: *mut vtx::VortexCtx,
    tls_initialized: bool,
    sasl_initialized: bool,
}

pub type OnAcceptConnection =
    fn(conn: conn::Connection) -> bool;
pub type OnStartChannel =
    fn(conn: conn::Connection,
       ch_no: u32) -> bool;
pub type OnCloseChannel =
    fn(conn: conn::Connection,
       ch_no: u32) -> bool;
pub type OnFrameReceived =
    fn(conn: conn::Connection,
       ch: ch::Channel,
       frame: &[u8]);

extern "C" {
    fn strdup(s: *const raw::c_char) -> *mut raw::c_char;
}

unsafe extern "C" fn sasl_plain_validation(
    _conn: *mut vtx::VortexConnection,
    auth_id: *const raw::c_char,
    authz_id: *const raw::c_char,
    password: *const raw::c_char
) -> vtx::axl_bool {

    info!("SASL auth from {:?}/{:?} with password {:?}",
          CStr::from_ptr(auth_id),
          CStr::from_ptr(authz_id),
          CStr::from_ptr(password));

    1
}

unsafe extern "C" fn call_accept_handler(
    conn: *mut vtx::VortexConnection,
    user_data: vtx::axlPointer) -> vtx::axl_bool {

    if user_data.is_null() {
        debug!("No OnAcceptConnection handler defined.");
    } else {
        let handler: OnAcceptConnection = mem::transmute(user_data);
        handler(conn::Connection::for_raw(conn));
    }

    1
}

unsafe extern "C" fn call_start_channel_handler(
    channel_num: raw::c_int,
    conn: *mut vtx::VortexConnection,
    user_data: vtx::axlPointer) -> vtx::axl_bool {

    if user_data.is_null() {
        debug!("No OnStartChannel handler defined.");
        1
    } else {
        let handler: OnStartChannel = mem::transmute(user_data);
        if handler(conn::Connection::for_raw(conn), channel_num as u32) {
            1
        } else {
            0
        }
    }
}

unsafe extern "C" fn call_close_channel_handler(
    channel_num: raw::c_int,
    conn: *mut vtx::VortexConnection,
    user_data: vtx::axlPointer) -> vtx::axl_bool {

    if user_data.is_null() {
        debug!("No OnCloseChannel handler defined.");
        1
    } else {
        let handler: OnCloseChannel = mem::transmute(user_data);
        if handler(conn::Connection::for_raw(conn), channel_num as u32) {
            1
        } else {
            0
        }
    }
}

pub unsafe extern "C" fn call_frame_received_handler(
    channel: *mut vtx::VortexChannel,
    conn: *mut vtx::VortexConnection,
    frame: *mut vtx::VortexFrame,
    user_data: vtx::axlPointer) {

    if user_data.is_null() {
        debug!("No OnCloseChannel handler defined.");
    } else {
        let size = vtx::vortex_frame_get_payload_size(frame) as usize;
        let content = vtx::vortex_frame_get_payload(frame) as *const u8;
        let frame = slice::from_raw_parts(content, size);
        let handler: OnFrameReceived = mem::transmute(user_data);

        handler(
            conn::Connection::for_raw(conn),
            ch::Channel::for_raw(channel),
            frame)
    }
}

unsafe extern "C" fn accept_all_tls(
    _: *mut vtx::VortexConnection,
    server_name: *const raw::c_char)
    -> vtx::axl_bool {

    info!("TLS requested for {:?}", CStr::from_ptr(server_name));

    1
}

unsafe extern "C" fn cert_file_location(
    _: *mut vtx::VortexConnection,
    _: *const raw::c_char)
    -> *mut raw::c_char {

    let cert_file = CString::new("cert.pem").unwrap();
    strdup(cert_file.as_ptr())
}

unsafe extern "C" fn key_file_location(
    _: *mut vtx::VortexConnection,
    _: *const raw::c_char)
    -> *mut raw::c_char {

    let key_file = CString::new("cert.key").unwrap();
    strdup(key_file.as_ptr())
}

impl<'a> Context {
    pub fn new() -> Context {
        unsafe {
            let ctx = vtx::vortex_ctx_new();
            if ctx.is_null() {
                panic!("Vortex vtx didn't return a context.");
            }
            if vtx::vortex_init_ctx(ctx) == 0 {
                vtx::vortex_ctx_free(ctx);
                panic!("Could not initialize vortex context!");
            }

            Context {
                ctx,
                tls_initialized: false,
                sasl_initialized: false,
            }
        }
    }

    pub fn raw_handle(&self) -> *mut vtx::VortexCtx {
        self.ctx
    }

    pub fn log_enable(&self, log_state: LogLevel) {
        let mut level1 = 0;
        let mut level2 = 0;
        unsafe {
            match log_state {
                LogLevel::None => {}
                LogLevel::FirstLevel => {
                    level1 = 1;
                }
                LogLevel::SecondLevel => {
                    level1 = 1;
                    level2 = 1;
                }
            }
            vtx::vortex_log_enable(self.ctx, level1);
            vtx::vortex_log2_enable(self.ctx, level2);
        }
    }

    fn tls_init(&self) -> Result<(), BeepError> {
        unsafe {
            if vtx::vortex_tls_init(self.ctx) == 0 {
                Err(BeepError::TlsInitFailed)
            } else {
                Ok(())
            }
        }
    }

    fn sasl_init(&self) -> Result<(), BeepError> {
        unsafe {
            if vtx::vortex_sasl_init(self.ctx) == 0 {
                Err(BeepError::SaslInitFailed)
            } else {
                Ok(())
            }
        }
    }

    fn connect_server(
        &self,
        server: &str,
    ) -> Result<*mut vtx::VortexConnection, BeepError> {
        info!("Trying to connect to {}.", server);

        unsafe {
            let serv = CString::new(server).unwrap();
            let port = CString::new("10288").unwrap();
            let connection = vtx::vortex_connection_new(
                self.ctx,
                serv.as_ptr(),
                port.as_ptr(),
                None,
                ptr::null_mut(),
            );
            if vtx::vortex_connection_is_ok(connection, 0) == 0 {
                let failure = format!(
                    "Could not connect to the server {}, error was: {:?}",
                    server,
                    CStr::from_ptr(
                        vtx::vortex_connection_get_message(connection),
                    )
                );
                vtx::vortex_connection_close(connection);
                Err(BeepError::ConnectionFailed(failure))
            } else {
                info!("Connection to {} established.", server);
                Ok(connection)
            }
        }
    }

    fn set_default_tls_handlers(&self, tls: &mut settings::Tls) {
        unsafe {
            vtx::vortex_tls_set_default_ctx_creation(
                self.ctx,
                Some(tls::tls_create_ssl_context),
                tls as *mut settings::Tls as *mut raw::c_void,
            );
            vtx::vortex_tls_set_default_post_check(
                self.ctx,
                Some(tls::check_established_tls_connection),
                tls as *mut settings::Tls as *mut raw::c_void,
            );
        }
    }

    fn start_tls(
        &mut self,
        server: &str,
        connection: *mut vtx::VortexConnection,
    ) -> Result<*mut vtx::VortexConnection, BeepError> {

        unsafe {
            let mut vortex_status: vtx::VortexStatus = 0;
            let mut vortex_status_message: *mut raw::c_char = ptr::null_mut();
            let tls_connection = vtx::vortex_tls_start_negotiation_sync(
                connection,
                server.as_ptr() as *const i8,
                &mut vortex_status,
                &mut vortex_status_message,
            );
            if vtx::vortex_connection_is_ok(tls_connection, 0) == 0 {
                let error = format!(
                    "Cannot establish TLS layer, error was: {:?}",
                    CStr::from_ptr(
                        vtx::vortex_connection_get_message(tls_connection),
                    )
                );
                vtx::vortex_connection_close(tls_connection);
                Err(BeepError::TlsConnectFailed(error))
            } else if vortex_status != vtx::STATUS_OK {
                let error = format!(
                    "Cannot establish TLS layer, \
                             vortex says: {:?}",
                    CStr::from_ptr(vortex_status_message)
                );
                vtx::vortex_connection_close(tls_connection);
                Err(BeepError::TlsConnectFailed(error))
            } else {
                info!("TLS layer established.");
                Ok(tls_connection)
            }
        }
    }

    pub fn listen(
        &mut self,
        host: &'a str,
        handler: OnAcceptConnection,
        tls: Option<settings::TlsServer>,
    ) -> Result<(), BeepError> {

        // init SASL
        if !self.sasl_initialized {
            self.sasl_init()?;
            self.sasl_initialized = true;
        }

        // allow SASL
        unsafe {
            vtx::vortex_sasl_set_plain_validation(
                self.ctx,
                Some(sasl_plain_validation));
            vtx::vortex_sasl_accept_negotiation(
                self.ctx,
                vtx::SASL_PLAIN as *const u8 as *const i8);
        }

        // create server
        unsafe {
            let serv = CString::new(host).unwrap();
            let port = CString::new("10288").unwrap();
            vtx::vortex_listener_new(
                self.ctx,
                serv.as_ptr(),
                port.as_ptr(),
                None, ptr::null_mut());
        }

        // allow TLS
        if let Some(_) = tls {
            unsafe {
                vtx::vortex_tls_accept_negotiation(
                    self.ctx,
                    Some(accept_all_tls),
                    Some(cert_file_location),
                    Some(key_file_location));
            }
        }

        // register accept handler
        unsafe {
            vtx::vortex_listener_set_on_connection_accepted(
                self.ctx,
                Some(call_accept_handler),
                handler as *mut raw::c_void);
        }

        Ok(())
    }

    pub fn wait_listener(&self) {
        unsafe {
            vtx::vortex_listener_wait(self.ctx);
        }
    }

    pub fn register_profile(
        &mut self,
        profile: &'a str,
        on_start_channel: OnStartChannel,
        on_close_channel: OnCloseChannel,
        on_frame_received: OnFrameReceived) {

        let profile = CString::new(profile).unwrap();

        unsafe {
            vtx::vortex_profiles_register(
                self.ctx,
                profile.as_ptr(),
                Some(call_start_channel_handler),
                on_start_channel as *mut raw::c_void,
                Some(call_close_channel_handler),
                on_close_channel as *mut raw::c_void,
                Some(call_frame_received_handler),
                on_frame_received as *mut raw::c_void);
        }
    }

    pub fn connect(
        &mut self,
        tls: Option<settings::Tls>,
        server: &'a str,
    ) -> Result<conn::Connection, BeepError> {

        // initialize TLS
        let use_tls = tls.is_some();
        if let Some(mut tls) = tls {
            if !self.tls_initialized {
                self.tls_init()?;
                self.tls_initialized = true;
            }

            self.set_default_tls_handlers(&mut tls);
        }

        // initialize SASL
        if !self.sasl_initialized {
            self.sasl_init()?;
            self.sasl_initialized = true;
        }

        let connection = self.connect_server(server)?;

        if use_tls {
            let tls_connection = self.start_tls(server, connection)?;
            Ok(conn::Connection::for_raw(tls_connection))
        } else {
            warn!("WARNING: TLS layer is disabled");
            Ok(conn::Connection::for_raw(connection))
        }
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        if !self.ctx.is_null() {
            unsafe {
                vtx::vortex_exit_ctx(self.ctx, 1);
            }
        }
    }
}
