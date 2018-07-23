extern crate autotools;

use autotools::Config;
use std::env;
use std::fs::File;
use std::process::{Command, Stdio};

fn main() -> std::io::Result<()> {
    let pkg_config_path = format!("{}/lib/pkgconfig",
                                  env::var("OUT_DIR").unwrap());

    Config::new("libaxl")
        .disable("-axl-knife", None)
        .disable("-py-axl", None)
        .build();

    Command::new("patch")
        .arg("-p1")
        .arg("--forward")
        .current_dir("libvortex")
        .stdin(Stdio::from(File::open("vortex_openssl11.patch")?))
        .status()
        .expect("Failed to patch vortex");

    let dst = Config::new("libvortex")
        .disable("-py-vortex", None)
        .env("PKG_CONFIG", "pkg-config --static")
        .env("PKG_CONFIG_PATH", pkg_config_path)
        .build();

    println!("cargo:rustc-link-search=native={}/lib", dst.display());
    println!("cargo:rustc-link-lib=static=axl");
    println!("cargo:rustc-link-lib=static=vortex-1.1");
    println!("cargo:rustc-link-lib=static=vortex-sasl-1.1");
    println!("cargo:rustc-link-lib=static=vortex-tls-1.1");

    Ok(())
}
