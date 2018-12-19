// Vortex types
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _VortexCtx {
    _unused: [u8; 0],
}
pub type VortexCtx = _VortexCtx;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _VortexConnection {
    _unused: [u8; 0],
}
pub type VortexConnection = _VortexConnection;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _VortexChannel {
    _unused: [u8; 0],
}
pub type VortexChannel = _VortexChannel;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _VortexFrame {
    _unused: [u8; 0],
}
pub type VortexFrame = _VortexFrame;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _WaitReplyData {
    _unused: [u8; 0],
}
pub type WaitReplyData = _WaitReplyData;
pub type VortexTlsCtxCreation =
    ::std::option::Option<
        unsafe extern "C" fn(connection: *mut VortexConnection,
                             user_data: axlPointer)
                             -> axlPointer,
    >;
pub type VortexConnectionNew =
    ::std::option::Option<
        unsafe extern "C" fn(connection: *mut VortexConnection,
                             user_data: axlPointer),
    >;
pub type VortexTlsPostCheck =
    ::std::option::Option<
        unsafe extern "C" fn(connection: *mut VortexConnection,
                             user_data: axlPointer,
                             ssl: axlPointer,
                             ctx: axlPointer)
                             -> axl_bool,
    >;
pub type VortexOnChannelCreated =
    ::std::option::Option<
        unsafe extern "C" fn(channel_num: ::std::os::raw::c_int,
                             channel: *mut VortexChannel,
                             conn: *mut VortexConnection,
                             user_data: axlPointer),
    >;
pub type VortexOnCloseChannel =
    ::std::option::Option<
        unsafe extern "C" fn(channel_num: ::std::os::raw::c_int,
                             connection: *mut VortexConnection,
                             user_data: axlPointer)
                             -> axl_bool,
    >;
pub type VortexOnFrameReceived =
    ::std::option::Option<
        unsafe extern "C" fn(channel: *mut VortexChannel,
                             connection: *mut VortexConnection,
                             frame: *mut VortexFrame,
                             user_data: axlPointer),
    >;
pub type VortexStatus = u32;
pub const STATUS_OK: VortexStatus = 2;
pub type VortexSaslProperties = u32;
pub const SASL_AUTH_ID: VortexSaslProperties = 1;
pub const SASL_PASSWORD: VortexSaslProperties = 3;
pub const SASL_PLAIN: &'static [u8; 32usize] =
    b"http://iana.org/beep/SASL/PLAIN\0";

// AXL types
pub type axl_bool = ::std::os::raw::c_int;
pub type axlPointer = *mut ::std::os::raw::c_void;
pub type axlDestroyFunc =
    ::std::option::Option<unsafe extern "C" fn(ptr: axlPointer)>;

// Context handling
extern "C" {
    pub fn vortex_ctx_new() -> *mut VortexCtx;
}

extern "C" {
    pub fn vortex_init_ctx(ctx: *mut VortexCtx) -> axl_bool;
}

extern "C" {
    pub fn vortex_exit_ctx(ctx: *mut VortexCtx, free_ctx: axl_bool);
}

extern "C" {
    pub fn vortex_ctx_free(ctx: *mut VortexCtx);
}

// Connection handling
extern "C" {
    pub fn vortex_connection_new(
        ctx: *mut VortexCtx,
        host: *const ::std::os::raw::c_char,
        port: *const ::std::os::raw::c_char,
        on_connected: VortexConnectionNew,
        user_data: axlPointer,
    ) -> *mut VortexConnection;
}

extern "C" {
    pub fn vortex_connection_is_ok(
        connection: *mut VortexConnection,
        free_on_fail: axl_bool,
    ) -> axl_bool;
}

extern "C" {
    pub fn vortex_connection_close(
        connection: *mut VortexConnection,
    ) -> axl_bool;
}

extern "C" {
    pub fn vortex_connection_get_message(
        connection: *mut VortexConnection,
    ) -> *const ::std::os::raw::c_char;
}

extern "C" {
    pub fn vortex_connection_get_channel(
        connection: *mut VortexConnection,
        channel_num: ::std::os::raw::c_int,
    ) -> *mut VortexChannel;
}

// Channel handling
extern "C" {
    pub fn vortex_channel_new(
        connection: *mut VortexConnection,
        channel_num: ::std::os::raw::c_int,
        profile: *const ::std::os::raw::c_char,
        close: VortexOnCloseChannel,
        close_user_data: axlPointer,
        received: VortexOnFrameReceived,
        received_user_data: axlPointer,
        on_channel_created: VortexOnChannelCreated,
        user_data: axlPointer,
    ) -> *mut VortexChannel;
}

extern "C" {
    pub fn vortex_channel_create_wait_reply() -> *mut WaitReplyData;
}

extern "C" {
    pub fn vortex_channel_send_msg(
        channel: *mut VortexChannel,
        message: *const ::std::os::raw::c_void,
        message_size: usize,
        msg_no: *mut ::std::os::raw::c_int,
    ) -> axl_bool;
}

// Logging
extern "C" {
    pub fn vortex_log_enable(ctx: *mut VortexCtx, status: axl_bool);
}
extern "C" {
    pub fn vortex_log2_enable(ctx: *mut VortexCtx, status: axl_bool);
}

// TLS
extern "C" {
    pub fn vortex_tls_init(ctx: *mut VortexCtx) -> axl_bool;
}

extern "C" {
    pub fn vortex_tls_set_default_ctx_creation(
        ctx: *mut VortexCtx,
        ctx_creation: VortexTlsCtxCreation,
        user_data: axlPointer,
    );
}
extern "C" {
    pub fn vortex_tls_set_default_post_check(
        ctx: *mut VortexCtx,
        post_check: VortexTlsPostCheck,
        user_data: axlPointer,
    );
}

extern "C" {
    pub fn vortex_tls_start_negotiation_sync(
        connection: *mut VortexConnection,
        serverName: *const ::std::os::raw::c_char,
        status: *mut VortexStatus,
        status_message: *mut *mut ::std::os::raw::c_char,
    ) -> *mut VortexConnection;
}

// SASL
extern "C" {
    pub fn vortex_sasl_init(ctx: *mut VortexCtx) -> axl_bool;
}

extern "C" {
    pub fn vortex_sasl_set_propertie(
        connection: *mut VortexConnection,
        prop: VortexSaslProperties,
        value: *mut ::std::os::raw::c_char,
        value_destroy: axlDestroyFunc,
    ) -> axl_bool;
}

extern "C" {
    pub fn vortex_sasl_start_auth_sync(
        connection: *mut VortexConnection,
        profile: *const ::std::os::raw::c_char,
        status: *mut VortexStatus,
        status_message: *mut *mut ::std::os::raw::c_char,
    );
}

extern "C" {
    pub fn vortex_sasl_is_authenticated(
        connection: *mut VortexConnection,
    ) -> axl_bool;
}
