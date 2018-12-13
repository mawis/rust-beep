extern crate cmake;

fn main() -> std::io::Result<()> {
    let axl = cmake::build("libaxl");
    let vortex = cmake::build("libvortex");

    println!("cargo:rustc-link-lib=gsasl");
    println!("cargo:rustc-link-lib=ssl");
    println!("cargo:rustc-link-search=native={}", axl.display());
    println!("cargo:rustc-link-lib=static=axl");
    println!("cargo:rustc-link-search=native={}", vortex.display());
    println!("cargo:rustc-link-lib=static=vortex");

    Ok(())
}
