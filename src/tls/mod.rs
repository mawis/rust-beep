use foreign_types_shared::ForeignTypeRef;
use libc::size_t;
use settings;
use std::ffi::{CStr, CString};
use std::os::raw;
use std::ptr;
use std::string::String;
use std::vec::Vec;
use openssl::nid::Nid;
use openssl::x509::X509Ref;
use vtx;

#[allow(non_camel_case_types, non_upper_case_globals, dead_code,
        non_snake_case)]
mod openssl;
#[allow(non_camel_case_types, non_upper_case_globals, dead_code,
        non_snake_case)]

extern "C" {
    pub fn strlen(__s: *const raw::c_char) -> size_t;
}

unsafe fn matching_hostnames(
    hostname: *const raw::c_char,
    certname: &str,
    wildcard_okay: bool,
) -> bool {

    let hostname = CStr::from_ptr(hostname).to_str();

    // sanity check
    if let Err(msg) = hostname {
        info!("no match, hostname: {}", msg);
        return false;
    }

    let hostname = hostname.unwrap();

    debug!("Checking hostname {:?} against {:?} (wildcards: {})",
        hostname, certname, wildcard_okay);

    // wildcard in certificate?
    if wildcard_okay && certname.contains("*") {
        // we hace to use wildcard aware checking

        // certname has to start with "*."
        if !certname.starts_with("*.") {
            info!("Certificate has a wildcard, but not at the beginning.");
            return false;
        }

        // there must be at least two lables in the hostname
        let hostname_domain =
            hostname.split(".").skip(1).collect::<Vec<_>>().join(".");
        if hostname_domain.is_empty() {
            info!("Too few labels in the hostname.");
            return false;
        }

        // there must be something behind the wildcard
        let certname_domain: String = certname.chars().skip(2).collect();
        if certname_domain.is_empty() {
            info!("Wildcard certificate name invalid.");
            return false;
        }

        // compare domain part
        debug!("Comparing {} with {}", certname_domain, hostname_domain);
        return certname_domain.to_lowercase() == hostname_domain.to_lowercase();
    } else {
        // return true if equals ignore case
        return hostname.to_lowercase() == certname.to_lowercase();
    }
}

unsafe fn tls_check_hostname(
    cert: &X509Ref,
    hostname: *const raw::c_char,
    wildcard_okay: bool,
) -> bool {
    let mut dns_name_found = false;

    // sanity check
    if hostname.is_null() {
        warn!("Cannot check hostname, hostname is null");
        return false;
    }

    // search subjectAltName/dNSName extension
    if let Some(subject_alt_names) = cert.subject_alt_names() {
        for subject_alt_name in subject_alt_names {
            if let Some(dns_name) = subject_alt_name.dnsname() {
                // we found a dNSName
                dns_name_found = true;

                debug!("dNSName: {}", dns_name);

                // special compare because of wildcard checking
                if matching_hostnames(
                    hostname,
                    dns_name,
                    wildcard_okay) {
                    debug!("Certificate accepted by subjectAltName/dNSName");
                    return true;
                }
            }
        }
    }

    // search for hostname in commonName
    // (only if there were no subjectAltName/dNSName extensions
    // - see RFC 2818, sect 3.1)
    if !dns_name_found {
        let cert_subject_name = cert.subject_name();
        let common_names = cert_subject_name.entries_by_nid(Nid::COMMONNAME);

        for common_name in common_names {
            let common_name = common_name.data();
            if let Ok(common_name) = common_name.as_utf8() {
                if matching_hostnames(
                    hostname,
                    &common_name,
                    wildcard_okay) {
                    debug!("Certificate accepted by commonName");
                    return true;
                }
            }
        }
    }

    false
}

fn subject(cert: &X509Ref) -> String {
    let subject_name = cert.subject_name();
    let entries = subject_name.entries();

    entries.flat_map(|entry| entry.data().as_utf8())
        .map(|s| s.to_string())
        .collect::<Vec<String>>()
        .join("/")
}

pub extern "C" fn check_established_tls_connection(
    _connection: *mut vtx::VortexConnection,
    user_data: vtx::axlPointer,
    ssl: vtx::axlPointer,
    _ctx: vtx::axlPointer,
) -> vtx::axl_bool {

    let settings: *mut settings::Tls = user_data as *mut settings::Tls;
    let ssl = ssl as *const openssl::ssl_st;

    unsafe {

        debug!("Checking established TLS layer.");

        // get cert verification result from OpenSSL
        let ssl_verify_result = openssl::SSL_get_verify_result(ssl);
        if ssl_verify_result != openssl::X509_V_OK as raw::c_long {
            warn!(
                "Server certificate verification failed: {:?}",
                CStr::from_ptr(
                    openssl::X509_verify_cert_error_string(ssl_verify_result),
                )
            );
            if (*settings).tls_insecure {
                info!("Accepting certificate anyway by command line request.");
                return 1;
            }
            return 0;
        }

        // get peer certificate
        let peer_certificate = openssl::SSL_get_peer_certificate(ssl);

        if peer_certificate.is_null() {
            warn!("Could not get peer certificate.");
            return 0;
        }
        let cert = X509Ref::from_ptr(
            peer_certificate as *mut <X509Ref as ForeignTypeRef>::CType);

        info!("Server certificate: {:?}", subject(cert));

        // verify the hostname in the certificate
        let server = CString::new((*settings).server).unwrap();
        if !tls_check_hostname(
            cert,
            server.as_ptr(),
            (*settings).tls_allow_wildcard,
        )
        {
            warn!("Server certificate not valid for {}", (*settings).server);
            if (*settings).tls_insecure {
                info!(
                    "Accepting certificate for wrong subject by command \
                       line request."
                );
                return 1;
            }
            return 0;
        }

        1
    }
}

/// Callback used to create SSL contexts.
///
/// This gets registered in Vortex
pub extern "C" fn tls_create_ssl_context(
    _connection: *mut vtx::VortexConnection,
    user_data: vtx::axlPointer,
) -> vtx::axlPointer {

    let settings: *mut settings::Tls = user_data as *mut settings::Tls;

    // sanity check
    if settings.is_null() {
        warn!("No settings were there ...");
        return ptr::null_mut();
    }

    // create context
    unsafe {
        let ssl_ctx = openssl::SSL_CTX_new(openssl::TLSv1_client_method());

        let capath = (*settings).capath.unwrap_or("");
        let cacert = (*settings).cacert.unwrap_or("");

        debug!("CApath: {:?} / CAcert: {:?}", capath, cacert);

        if !capath.is_empty() || !cacert.is_empty() {
            let path = CString::new(capath).unwrap();
            let cert = CString::new(cacert).unwrap();
            let path = if capath.is_empty() {
                ptr::null_mut()
            } else {
                path.as_ptr()
            };
            let cert = if cacert.is_empty() {
                ptr::null_mut()
            } else {
                cert.as_ptr()
            };
            if openssl::SSL_CTX_load_verify_locations(ssl_ctx, cert, path) ==
                0
            {
                error!(
                    "Could not configure CA locations \
                            (file={:?}, dir={:?}).",
                    (*settings).cacert,
                    (*settings).capath
                );
                openssl::SSL_CTX_free(ssl_ctx);
                return ptr::null_mut();
            }
        } else {
            if openssl::SSL_CTX_set_default_verify_paths(ssl_ctx) == 0 {
                error!("Could not set default verify paths on libssl");
                openssl::SSL_CTX_free(ssl_ctx);
                return ptr::null_mut();
            }
        }

        return ssl_ctx as *mut raw::c_void;
    }
}
