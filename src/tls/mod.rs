use settings;
use std::ffi::{CStr, CString};
use std::os::raw;
use std::ptr;
use std::string::String;
use std::vec::Vec;
use vtx;

#[allow(non_camel_case_types, non_upper_case_globals, dead_code,
        non_snake_case)]
mod openssl;
#[allow(non_camel_case_types, non_upper_case_globals, dead_code,
        non_snake_case)]
mod x509v3;

extern "C" {
    pub fn strlen(__s: *const raw::c_char) -> raw::c_ulong;
}

unsafe fn matching_hostnames(
    hostname: *const raw::c_char,
    certname: *const raw::c_char,
    wildcard_okay: bool,
) -> bool {

    let hostname = CStr::from_ptr(hostname).to_str();
    let certname = CStr::from_ptr(certname).to_str();

    // sanity check
    if let Err(msg) = hostname {
        info!("no match, hostname: {}", msg);
        return false;
    }
    if let Err(msg) = certname {
        info!("no match, certname: {}", msg);
        return false;
    }

    let hostname = hostname.unwrap();
    let certname = certname.unwrap();

    // wildcard in certificate?
    if wildcard_okay && certname.contains("*") {
        // we hace to use wildcard aware checking

        // certname has to start with "*."
        if !certname.starts_with("*.") {
            return false;
        }

        // there must be at least two lables in the hostname
        let hostname_domain =
            hostname.split(".").skip(1).collect::<Vec<_>>().join(".");
        if hostname_domain.is_empty() {
            return false;
        }

        // there must be something behind the wildcard
        let certname_domain: String = certname.chars().skip(2).collect();
        if certname_domain.is_empty() {
            return false;
        }

        // compare domain part
        return certname_domain.to_lowercase() == hostname_domain.to_lowercase();
    } else {
        // return true if equals ignore case
        return hostname.to_lowercase() == certname.to_lowercase();
    }
}

unsafe fn tls_check_hostname(
    cert: *mut openssl::X509,
    hostname: *const raw::c_char,
    wildcard_okay: bool,
) -> bool {
    let mut dns_name_found = false;
    let mut hostname_found = false;

    // sanity check
    if cert.is_null() || hostname.is_null() {
        warn!(
            "Cannot check hostname, parameters are missing \
               ({:p}, {:p})",
            cert,
            hostname
        );
        return false;
    }

    // search subjectAltName/dNSName extension
    let subject_alt_name = openssl::X509_get_ext_d2i(
        cert,
        openssl::NID_subject_alt_name as i32,
        ptr::null_mut(),
        ptr::null_mut(),
    ) as *const openssl::stack_st;
    if !subject_alt_name.is_null() {
        let number_of_subject_alt_names =
            openssl::sk_num(subject_alt_name);
        (0..number_of_subject_alt_names).for_each(|c| {
            let entry = openssl::sk_value(subject_alt_name, c) as
                *mut x509v3::GENERAL_NAME_st;

            // sanity check
            if entry.is_null() {
                return;
            }

            // we only care about dNSName
            if (*entry).type_ != x509v3::GEN_DNS as i32 {
                return;
            }

            // we found a dNSName
            dns_name_found = true;

            // sanity checks
            let ia5 = (*entry).d.ia5;
            if ia5.is_null() || (*ia5).length <= 0 || (*ia5).data.is_null() ||
                strlen((*ia5).data as *mut i8) != (*ia5).length as u64
            {
                debug!(
                    "Internal sanity check failed. \
                            Expectations on subjectAltName entry were wrong."
                );
                return;
            }

            // special compare because of wildcard checking
            if matching_hostnames(
                hostname,
                (*ia5).data as *mut raw::c_char,
                wildcard_okay,
            )
            {
                hostname_found = true;
                return;
            }
        });
    }

    // search for hostname in commonName
    // (only if there were no subjectAltName/dNSName extensions
    // - see RFC 2818, sect 3.1)
    if !hostname_found && !dns_name_found {
        let cert_subject_name = openssl::X509_get_subject_name(cert);

        if cert_subject_name.is_null() {
            info!(
                "DN check requested, but could not get subject from \
                   certificate."
            );
        } else {
            let cn_length = openssl::X509_NAME_get_text_by_NID(
                cert_subject_name,
                openssl::NID_commonName as i32,
                ptr::null_mut(),
                0,
            );

            if cn_length == -1 {
                info!(
                    "Certificate does not contain a CN label in \
                       the subject."
                );
            } else if cn_length >= 1024 {
                warn!("Cannot handle CN label ... it's too big.");
            } else {
                let mut common_name_buffer = [0i8; 1024];
                let common_name: *mut i8 =
                    &mut common_name_buffer as *mut [i8; 1024] as *mut i8;

                if x509v3::X509_NAME_get_text_by_NID(
                    cert_subject_name as *mut x509v3::X509_name_st,
                    openssl::NID_commonName as i32,
                    common_name,
                    1024,
                ) == -1
                {
                    warn!("Problem reading commonName");
                } else {
                    if matching_hostnames(
                        hostname,
                        common_name,
                        wildcard_okay,
                    )
                    {
                        hostname_found = true;
                    }
                }
            }
        }
    }

    hostname_found
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
        if ssl_verify_result != openssl::X509_V_OK as i64 {
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
        let peer_certificate_subject_name =
            openssl::X509_get_subject_name(peer_certificate);
        let mut buffer = [0i8; 1024];
        openssl::X509_NAME_oneline(
            peer_certificate_subject_name,
            buffer.as_mut_ptr(),
            buffer.len() as i32,
        );
        info!(
            "Server certificate: {:?}",
            CStr::from_ptr(buffer.as_ptr() as *const raw::c_char)
        );

        // verify the hostname in the certificate
        let server = CString::new((*settings).server).unwrap();
        if !tls_check_hostname(
            peer_certificate,
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
        return ptr::null_mut();
    }

    // create context
    unsafe {
        let ssl_ctx = openssl::SSL_CTX_new(openssl::TLSv1_client_method());

        let capath = (*settings).capath.unwrap_or("");
        let cacert = (*settings).cacert.unwrap_or("");

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
