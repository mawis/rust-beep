#[derive(Debug)]
pub struct Tls<'a> {
    pub server: &'a str,
    pub cacert: Option<&'a str>,
    pub capath: Option<&'a str>,
    pub tls_allow_wildcard: bool,
    pub tls_insecure: bool,
}

pub struct TlsServer {
}

pub struct Sasl<'a> {
    pub auth_id: &'a str,
    pub password: &'a str,
}

impl <'a> Tls<'a> {
    pub fn for_server(server: &'a str) -> Tls<'a> {
        Tls {
            server,
            cacert: None,
            capath: None,
            tls_allow_wildcard: false,
            tls_insecure: false,
        }
    }

    pub fn cacert(&self, cacert: Option<&'a str>) -> Tls<'a> {
        Tls {
            cacert,
            .. *self
        }
    }

    pub fn capath(&self, capath: Option<&'a str>) -> Tls<'a> {
        Tls {
            capath,
            .. *self
        }
    }

    pub fn allow_wildcard(&self, tls_allow_wildcard: bool) -> Tls<'a> {
        Tls {
            tls_allow_wildcard,
            .. *self
        }
    }

    pub fn insecure(&self, tls_insecure: bool) -> Tls<'a> {
        Tls {
            tls_insecure,
            .. *self
        }
    }
}

impl <'a> Sasl<'a> {
    pub fn for_user(auth_id: &'a str, password: &'a str) -> Sasl<'a> {
        Sasl {
            auth_id,
            password,
        }
    }
}

impl TlsServer {
    pub fn new() -> TlsServer {
        TlsServer{}
    }
}
