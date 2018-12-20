use super::*;

use std::ffi::{CStr, CString};
use std::os::raw;
use std::ptr;

pub struct Context {
    ctx: *mut vtx::VortexCtx,
    tls_initialized: bool,
    sasl_initialized: bool,
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
                server.as_ptr() as *const raw::c_char,
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

    pub fn connect(
        &mut self,
        tls: &mut Option<settings::Tls>,
        server: &'a str,
    ) -> Result<conn::Connection, BeepError> {

        // initialize TLS
        let use_tls = tls.is_some();
        if let Some(ref mut tls) = tls {
            if !self.tls_initialized {
                self.tls_init()?;
                self.tls_initialized = true;
            }

            self.set_default_tls_handlers(tls);
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
