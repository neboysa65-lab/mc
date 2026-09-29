//! Embed an application manifest (requireAdministrator: WinTun adapter
//! creation and route installation need elevation) when a windres is
//! available (windows-gnu cross builds; MSVC hosts skip this gracefully).

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let target = std::env::var("TARGET").unwrap_or_default();
    if !target.contains("windows") {
        return;
    }
    let windres = if target.starts_with("x86_64") {
        "x86_64-w64-mingw32-windres"
    } else if target.starts_with("aarch64") {
        "aarch64-w64-mingw32-windres"
    } else if target.starts_with("i686") {
        "i686-w64-mingw32-windres"
    } else {
        return;
    };
    let have_windres = std::process::Command::new(windres)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !have_windres {
        println!(
            "cargo:warning=windres not found: no embedded manifest \
             (run the app as Administrator manually)"
        );
        return;
    }
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR");
    let manifest = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity version="0.1.2.0" processorArchitecture="*" name="mcvpn" type="win32"/>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>
"#;
    std::fs::write(format!("{out_dir}/mcvpn.exe.manifest"), manifest).expect("write manifest");
    std::fs::write(
        format!("{out_dir}/manifest.rc"),
        "1 24 \"mcvpn.exe.manifest\"\r\n",
    )
    .expect("write rc");
    let status = std::process::Command::new(windres)
        .current_dir(&out_dir)
        .arg("manifest.rc")
        .arg("-O")
        .arg("coff")
        .arg("-o")
        .arg("manifest.o")
        .status()
        .expect("windres run");
    assert!(status.success(), "windres failed");
    println!("cargo:rustc-link-arg={out_dir}/manifest.o");
}
