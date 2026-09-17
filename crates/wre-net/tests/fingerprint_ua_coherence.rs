//! The TLS fingerprint and the sandbox's JS surface must claim the SAME browser.
//!
//! They disagreed by eleven major versions: the handshake and the User-Agent
//! header said Chrome 140 while `navigator.userAgent` and `userAgentData` inside
//! the sandbox said Chrome 151. Akamai's sensor reports what JS sees and the edge
//! sees the header, so every request carried a self-contradiction and Disney
//! answered 502 BEFORE ANY SCRIPT RAN — no sensor was ever evaluated.
//!
//! 151 was doubly wrong: no such Chrome has shipped, so wreq-util cannot offer a
//! matching fingerprint at all. A version claim with no corresponding TLS profile
//! is unfixable by construction, which is what this test exists to prevent.

use std::path::Path;

/// Every `Chrome/<major>` the JS surface claims AT RUNTIME.
///
/// Reads BOTH the asset and `BUNDLED_CHROME`, because the asset is not the
/// authority: `Profile::desktop_chrome()` calls `retune_chrome(BUNDLED_CHROME)`,
/// which rewrites every version field in the loaded JSON. An earlier version of
/// this test read only the asset — so editing the JSON alone passed the test
/// while the runtime still emitted the old version, and the fix shipped inert.
fn surface_majors() -> Vec<u32> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../wre-sandbox/src/profile.rs");
    let code = std::fs::read_to_string(&src).expect("profile.rs");
    let marker = "const BUNDLED_CHROME: &str = \"";
    let at = code.find(marker).expect("BUNDLED_CHROME is declared");
    let rest = &code[at + marker.len()..];
    let retuned: u32 = rest
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .expect("BUNDLED_CHROME is a number");

    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../wre-sandbox/assets/desktop-chrome.json");
    let raw = std::fs::read_to_string(&path).expect("surface asset");
    let mut out = Vec::new();
    for (idx, _) in raw.match_indices("Chrome/") {
        let rest = &raw[idx + "Chrome/".len()..];
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        if let Ok(major) = digits.parse::<u32>() {
            out.push(major);
        }
    }
    assert!(!out.is_empty(), "no Chrome/<version> found in the surface asset");
    // The retune value is what the page actually sees, so it must agree too.
    out.push(retuned);
    out
}

#[test]
fn the_tls_profile_claims_the_same_chrome_as_the_js_surface() {
    let fingerprint = wre_net::emulate::Fingerprint::default();
    let agent = fingerprint.user_agent().expect("profile emits a user agent");

    let idx = agent.find("Chrome/").expect("profile UA names Chrome");
    let tls_major: u32 = agent[idx + "Chrome/".len()..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .expect("numeric major");

    for surface_major in surface_majors() {
        assert_eq!(
            surface_major, tls_major,
            "JS surface claims Chrome {surface_major} but the TLS profile presents \
             Chrome {tls_major}. Akamai cross-checks these and answers 502 before \
             running any script. Update BOTH crates/wre-sandbox/assets/desktop-chrome.json \
             and the default Profile in crates/wre-net/src/emulate.rs together."
        );
    }
}
