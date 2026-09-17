use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};
use url::Url;

static AKAM_SRC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)src\s*=\s*["']([^"']*/akam/(\d+)/([A-Za-z0-9_-]+)(?:\?[^"']*)?)["']"#)
        .expect("akam pattern")
});

static SCRIPT_SRC: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?is)<script[^>]*\ssrc\s*=\s*["']([^"']+)["']"#).expect("script pattern"));

static BAZA: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)bazadebezolkohpepadr\s*=\s*["'](\d+)["']"#).expect("baza pattern")
});

static CHALLENGE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(sec-cpt|_sec/cp_challenge|challenge_id|cp_challenge)"#).expect("challenge pattern")
});

/// Path segments are base64url-ish tokens. NO LENGTH BOUND: the previous
/// `{1,24}` was an arbitrary guess about a value Akamai rotates, and when it
/// rotated to a 27-character first segment every call failed for 23 hours.
/// A bound picked to admit today's path would only defer the same outage.
static SEGMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_-]+$").expect("segment pattern"));

/// Selectivity comes from TOKEN SHAPE, not length: an Akamai sensor path is
/// generated, so across the whole path it mixes letter case AND carries digits.
/// Human-authored asset paths (`/assets/js/vendor/polyfills`,
/// `/static/bundles/application-a7f3.../runtime`) are lowercase words, with or
/// without digits, and are rejected.
///
/// WHOLE-PATH, never per-segment: Maersk's real sensor has an all-lowercase
/// `2ib` segment, so a per-segment rule would reject a known-good path.
///
/// This is calibrated on two real captures. An all-lowercase rotation would
/// fail it CLOSED — which is why `Surface::rejected` exists: a near-miss is
/// reported rather than silently dropped, so the next rotation is diagnosed in
/// minutes instead of a day.
fn looks_generated(segments: &[&str]) -> bool {
    let mut upper = false;
    let mut lower = false;
    let mut digit = false;
    for part in segments {
        for ch in part.chars() {
            if ch.is_ascii_uppercase() {
                upper = true;
            } else if ch.is_ascii_lowercase() {
                lower = true;
            } else if ch.is_ascii_digit() {
                digit = true;
            }
        }
    }
    upper && lower && digit
}

const MARK: &str = "aeiouy13579";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    Sensor,
    Pixel,
    Obfuscated,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Script {
    pub kind: Kind,
    pub url: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub generation: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Flags {
    pub force_secure: bool,
    pub bot_manager: bool,
    pub proof_of_work: bool,
    pub ip_reputation: bool,
    pub akid: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Config {
    pub segment: String,
    pub from_host: bool,
    pub bits: String,
    pub flags: Option<Flags>,
    pub note: Option<String>,
}

/// A script that ALMOST looked like the sensor, and the gate that stopped it.
///
/// `looks_obfuscated` used to reject silently, so a rotation that broke
/// discovery was indistinguishable from a page that genuinely carries no
/// sensor — the difference between a 23-hour outage and a 20-minute one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Rejected {
    pub url: String,
    /// Which gate rejected it: `cross-host`, `too-few-segments`, `akam-path`,
    /// `has-extension`, `charset`, or `not-generated`.
    pub gate: String,
    pub detail: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Surface {
    pub sensor: Option<Script>,
    /// Near-miss candidates, for diagnostics. Never used for selection.
    #[serde(default)]
    pub rejected: Vec<Rejected>,
    pub pixel_client: Option<Script>,
    pub pixel_post: Option<String>,
    pub baza: Option<String>,
    pub config: Option<Config>,
    pub scripts: Vec<Script>,
    pub challenge_page: bool,
}

impl Surface {
    pub fn is_protected(&self) -> bool {
        self.sensor.is_some() || self.pixel_client.is_some()
    }
}

pub fn discover(html: &str, base: &str) -> Surface {
    let mut akam = Vec::new();

    for found in AKAM_SRC.captures_iter(html) {
        let href = found.get(1).map_or("", |part| part.as_str());
        let generation = found
            .get(2)
            .and_then(|part| part.as_str().parse::<u32>().ok())
            .unwrap_or_default();
        let name = found.get(3).map_or("", |part| part.as_str()).to_string();
        let pixel = name.starts_with("pixel_");

        akam.push(Script {
            kind: if pixel { Kind::Pixel } else { Kind::Sensor },
            url: absolute(base, href),
            name,
            generation,
        });
    }

    let mut obfuscated = Vec::new();
    let mut rejected = Vec::new();

    for found in SCRIPT_SRC.captures_iter(html) {
        let href = found.get(1).map_or("", |part| part.as_str());
        if let Err(why) = classify(href, base) {
            // Keep only near-misses worth reading: a cross-host CDN bundle on
            // every page is noise, a path that cleared every gate but one is the
            // signal a rotation produces.
            if why.gate != "cross-host" && why.gate != "too-few-segments" {
                rejected.push(why);
            }
            continue;
        }

        obfuscated.push(Script {
            kind: Kind::Obfuscated,
            url: absolute(base, href),
            name: String::new(),
            generation: 0,
        });
    }

    let plain_akam = akam.iter().find(|script| script.kind == Kind::Sensor).cloned();
    let sensor = obfuscated.first().cloned().or_else(|| plain_akam.clone());

    let pixel_client = match (&sensor, &plain_akam) {
        (Some(chosen), Some(plain)) if chosen.url != plain.url => Some(plain.clone()),
        _ => akam
            .iter()
            .find(|script| script.kind == Kind::Pixel)
            .and_then(|pixel| {
                let hash = pixel.name.trim_start_matches("pixel_").to_string();
                plain_akam
                    .clone()
                    .filter(|plain| plain.name == hash)
            }),
    };

    let baza = BAZA
        .captures(html)
        .and_then(|found| found.get(1))
        .map(|part| part.as_str().to_string());

    let pixel_post = match (&baza, &pixel_client) {
        (Some(seed), Some(client)) => pixel_post_url(&client.url, seed),
        _ => akam
            .iter()
            .find(|script| script.kind == Kind::Pixel)
            .map(|script| script.url.split('?').next().unwrap_or_default().to_string()),
    };

    let config = sensor.as_ref().and_then(|script| read_config(&script.url));

    let mut scripts = akam;
    scripts.extend(obfuscated);

    Surface {
        rejected,
        sensor,
        pixel_client,
        pixel_post,
        baza,
        config,
        scripts,
        challenge_page: CHALLENGE.is_match(html),
    }
}

pub fn pixel_hash(seed: &str) -> Option<String> {
    let value = seed.parse::<i64>().ok()?;
    Some(format!("{:x}", 77 ^ value))
}

fn pixel_post_url(client: &str, seed: &str) -> Option<String> {
    let hash = pixel_hash(seed)?;
    let base = client.rsplit_once('/')?.0;
    Some(format!("{base}/pixel_{hash}"))
}

pub fn read_config(script_url: &str) -> Option<Config> {
    let parts: Vec<&str> = script_url.split('/').collect();
    if parts.len() < 4 {
        return None;
    }

    let segment = parts[parts.len() - 4].to_string();
    if segment.is_empty() || segment.len() % 2 != 0 {
        return None;
    }

    let from_host = Url::parse(script_url)
        .ok()
        .and_then(|parsed| parsed.host_str().map(|host| host == segment))
        .unwrap_or(false);

    let bits = bits_from(&segment);

    if bits.len() <= 3 {
        return Some(Config {
            segment,
            from_host,
            bits,
            flags: None,
            note: Some("too few bits, the config is not applied".to_string()),
        });
    }

    let bit = |index: usize| bits.as_bytes().get(index) == Some(&b'1');

    let flags = Flags {
        force_secure: bit(0),
        bot_manager: bit(1),
        proof_of_work: bit(2),
        ip_reputation: bit(3),
        akid: bits.len() > 4 && bit(4),
    };

    Some(Config { segment, from_host, bits, flags: Some(flags), note: None })
}

fn bits_from(segment: &str) -> String {
    let lower = segment.to_lowercase();
    let characters: Vec<char> = lower.chars().collect();
    let mut bits = String::new();

    let mut index = 0;
    while index < characters.len() {
        let first = MARK.contains(characters[index]);
        let second = characters
            .get(index + 1)
            .map(|found| MARK.contains(*found))
            .unwrap_or(false);

        bits.push(if first || second { '1' } else { '0' });
        index += 2;
    }

    bits
}

/// Classify a script `src` as the sensor shape, or name the gate that rejected it.
///
/// `Ok(())` means it qualifies. `Err(Rejected)` carries WHICH gate stopped it and
/// why — the diagnostic the silent-bool version could not give.
fn classify(href: &str, base: &str) -> Result<(), Rejected> {
    let reject = |gate: &str, detail: String| {
        Err(Rejected { url: href.to_string(), gate: gate.to_string(), detail })
    };

    // ── Same-host gate ────────────────────────────────────────────────────
    //
    // Handles THREE href forms. The protocol-relative one was previously
    // unguarded: the check keyed on `starts_with("http")`, so `//evilcdn/a/b/c/d`
    // skipped it entirely and could be selected as the sensor. Only dots in real
    // hostnames accidentally prevented that.
    let path = if href.starts_with("//") {
        let rest = &href[2..];
        let (host, tail) = match rest.find('/') {
            Some(at) => (&rest[..at], &rest[at..]),
            None => (rest, "/"),
        };
        let page_host = Url::parse(base).ok().and_then(|u| u.host_str().map(str::to_string));
        if page_host.as_deref() != Some(host) {
            return reject("cross-host", format!("protocol-relative //{host}"));
        }
        tail.split('?').next().unwrap_or_default().to_string()
    } else if href.starts_with("http") {
        let (Ok(target), Ok(page)) = (Url::parse(href), Url::parse(base)) else {
            return reject("cross-host", "unparseable absolute url".to_string());
        };
        if target.host_str() != page.host_str() {
            return reject(
                "cross-host",
                format!("{} != {}", target.host_str().unwrap_or("?"), page.host_str().unwrap_or("?")),
            );
        }
        target.path().to_string()
    } else {
        href.split('?').next().unwrap_or_default().to_string()
    };

    let segments: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();

    if segments.len() < 4 {
        return reject("too-few-segments", format!("{} < 4", segments.len()));
    }
    if path.contains("/akam/") {
        return reject("akam-path", "handled as a plain akam script".to_string());
    }
    if let Some(last) = segments.last()
        && last.contains('.')
    {
        return reject("has-extension", format!("last segment `{last}` contains a dot"));
    }
    if let Some(bad) = segments.iter().find(|part| !SEGMENT.is_match(part)) {
        return reject("charset", format!("segment `{bad}` is not base64url"));
    }
    if !looks_generated(&segments) {
        return reject(
            "not-generated",
            "path lacks the mixed-case + digit shape of a generated token".to_string(),
        );
    }
    Ok(())
}

fn absolute(base: &str, href: &str) -> String {
    match Url::parse(base).and_then(|parsed| parsed.join(href)) {
        Ok(joined) => joined.to_string(),
        Err(_) => href.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAERSK: &str = r#"
<html><head>
<script type="text/javascript">bazadebezolkohpepadr="1320943881"</script>
<script type="text/javascript" src="/akam/13/4ebc0144"></script>
<script type="text/javascript" src="/akam/13/pixel_4ebc0144?a=dD0xJmpzPW9mZg=="></script>
<script src="/pWSY7c1/2ib/AKfr/hFDsQoTHmWt/YwEfMkyRK8U/Y3g/AWJXAjJfBQ"></script>
</head><body></body></html>
"#;

    const PLAIN: &str = r#"<html><head>
<script src="https://www.example.com/akam/11/5c9e4a7b"></script>
</head></html>"#;

    /// Script `src` values taken verbatim from a Disney production capture
    /// 2026-09-16 (HTTP 200, 31,495 bytes, 4 script tags). The surrounding HTML
    /// is hand-assembled and carries 2 of those 4 — so this is a REAL-VALUE
    /// fixture, not a real BODY. It cannot express ordering among the page's
    /// actual scripts; the full body belongs under `captures/` if it ever needs
    /// to. Every
    /// disneyworld.disney.go.com page serves this sensor path; its FIRST segment
    /// is 27 characters.
    ///
    /// SEGMENT capped at 24 until this commit, so `looks_obfuscated` rejected the
    /// path, `discover` returned no sensor, and the client raised
    /// "names no Akamai sensor script" on every call. The dining availability
    /// sweep ran at 100% failure for 23 hours behind that one bound.
    const DISNEY: &str = r#"<html><head>
<script src="https://cdn1.parksmedia.wdprapps.disney.com/media/advanced-finder-spa/v8.7.0-4775/main-J2AX4UGU.js"></script>
<script src="/-0T4oBCNNNfKdwIJFIeqgzjlcoM/h1Yk2tpb3OJ84p/OUxrAQ/Wm/UNQBhWLG4"></script>
</head></html>"#;

    /// A long first segment must not hide the sensor.
    ///
    /// The gate that failed in production: segment 1 is 27 chars, and the cap
    /// was 24. Asserts the URL, not `is_some()`, so a wrong pick fails loudly.
    #[test]
    fn a_long_first_segment_does_not_hide_the_sensor() {
        let surface = discover(DISNEY, "https://disneyworld.disney.go.com/dining/");

        assert!(surface.is_protected());
        let sensor = surface.sensor.clone().expect("no sensor discovered");
        assert_eq!(sensor.kind, Kind::Obfuscated);
        assert!(
            sensor.url.ends_with("/-0T4oBCNNNfKdwIJFIeqgzjlcoM/h1Yk2tpb3OJ84p/OUxrAQ/Wm/UNQBhWLG4"),
            "discovered the wrong script: {}",
            sensor.url
        );
    }

    /// A rotation LONGER than any bound we might have guessed still discovers.
    ///
    /// This is the test the length cap could never pass: 24 failed on 27, and a
    /// cap of 64 fails on 70. Dropping the bound is what makes it green, which
    /// is the whole argument for replacing length with shape.
    #[test]
    fn a_seventy_character_segment_still_discovers() {
        const ROTATED: &str = r#"<html><head>
<script src="/-0T4oBCNNNfKdwIJFIeqgzjlcoM0T4oBCNNNfKdwIJFIeqgzjlcoM0T4oBCNNNfKdwIJ/h1Yk2tpb3OJ84p/OUxrAQ/Wm/UNQBhWLG4"></script>
</head></html>"#;
        let surface = discover(ROTATED, "https://disneyworld.disney.go.com/dining/");
        assert!(surface.sensor.is_some(), "a longer rotation must not break discovery");
    }

    /// `obfuscated.first()` takes DOCUMENT ORDER with no ranking, so a decoy
    /// listed before the sensor is selected instead of it.
    ///
    /// Both decoys here are same-host and extensionless — they clear the host
    /// gate, the segment-count gate and the extension gate. The length cap
    /// admitted the short one at 24 and the long one at 64, i.e. it never
    /// provided this selectivity at any bound. Shape does.
    #[test]
    fn a_same_host_app_bundle_ordered_before_the_sensor_is_not_selected() {
        const LONG_DECOY: &str = r#"<html><head>
<script src="/static/bundles/application-a7f3c9e12b4d6f8a0c5e2b1d9f7a3c60/runtime"></script>
<script src="/-0T4oBCNNNfKdwIJFIeqgzjlcoM/h1Yk2tpb3OJ84p/OUxrAQ/Wm/UNQBhWLG4"></script>
</head></html>"#;
        const SHORT_DECOY: &str = r#"<html><head>
<script src="/assets/js/vendor/polyfills"></script>
<script src="/-0T4oBCNNNfKdwIJFIeqgzjlcoM/h1Yk2tpb3OJ84p/OUxrAQ/Wm/UNQBhWLG4"></script>
</head></html>"#;

        for (label, html) in [("long", LONG_DECOY), ("short", SHORT_DECOY)] {
            let surface = discover(html, "https://disneyworld.disney.go.com/dining/");
            let sensor = surface.sensor.expect("no sensor discovered");
            assert!(
                sensor.url.ends_with("/UNQBhWLG4"),
                "{label} decoy was selected instead of the sensor: {}",
                sensor.url
            );
        }
    }

    /// A protocol-relative cross-host script must not be selected.
    ///
    /// The same-host gate keyed on `starts_with("http")`, so `//host/...` skipped
    /// it entirely. Only dots in real hostnames accidentally prevented a
    /// cross-host script from being chosen as the sensor.
    #[test]
    fn a_protocol_relative_cross_host_script_is_not_the_sensor() {
        const CROSS: &str = r#"<html><head>
<script src="//evilcdn/aB1/bBc2/cCd3/dDe4"></script>
<script src="/-0T4oBCNNNfKdwIJFIeqgzjlcoM/h1Yk2tpb3OJ84p/OUxrAQ/Wm/UNQBhWLG4"></script>
</head></html>"#;
        let surface = discover(CROSS, "https://disneyworld.disney.go.com/dining/");
        let sensor = surface.sensor.expect("no sensor discovered");
        assert!(sensor.url.ends_with("/UNQBhWLG4"), "cross-host script selected: {}", sensor.url);
    }

    /// A page with no sensor reports the near-misses that ALMOST qualified.
    ///
    /// This is the difference between a 23-hour outage and a 20-minute one: the
    /// error can say "one candidate cleared every gate but the charset" rather
    /// than only "no sensor here".
    #[test]
    fn a_near_miss_is_recorded_for_diagnostics() {
        const NEAR: &str = r#"<html><head>
<script src="/aB1/bB!2/cCd3/dDe4"></script>
</head></html>"#;
        let surface = discover(NEAR, "https://disneyworld.disney.go.com/dining/");
        assert!(surface.sensor.is_none());
        assert_eq!(surface.rejected.len(), 1, "near-miss not recorded: {:?}", surface.rejected);
        assert_eq!(surface.rejected[0].gate, "charset");
    }

    #[test]
    fn the_obfuscated_path_is_the_sensor_and_the_akam_script_is_the_pixel_client() {
        let surface = discover(MAERSK, "https://www.maersk.com/tracking/ABC1234567");

        let sensor = surface.sensor.clone().expect("sensor");
        assert_eq!(sensor.kind, Kind::Obfuscated);
        assert!(sensor.url.ends_with("/pWSY7c1/2ib/AKfr/hFDsQoTHmWt/YwEfMkyRK8U/Y3g/AWJXAjJfBQ"));

        let pixel = surface.pixel_client.clone().expect("pixel client");
        assert_eq!(pixel.url, "https://www.maersk.com/akam/13/4ebc0144");
        assert_eq!(surface.baza.as_deref(), Some("1320943881"));
        assert_eq!(surface.pixel_post.as_deref(), Some("https://www.maersk.com/akam/13/pixel_4ebc0144"));
        assert!(surface.is_protected());
        assert!(!surface.challenge_page);
    }

    #[test]
    fn a_page_with_only_an_akam_script_uses_it_as_the_sensor() {
        let surface = discover(PLAIN, "https://www.example.com/");
        let sensor = surface.sensor.expect("sensor");

        assert_eq!(sensor.kind, Kind::Sensor);
        assert_eq!(sensor.generation, 11);
        assert_eq!(sensor.name, "5c9e4a7b");
        assert!(surface.pixel_client.is_none());
    }

    #[test]
    fn the_pixel_post_path_comes_from_the_seed() {
        assert_eq!(pixel_hash("1320943881").as_deref(), Some("4ebc0144"));
    }

    #[test]
    fn the_config_segment_decodes_to_the_flag_bits() {
        let config = read_config("https://www.example.com/aBcDeF/gHiJkLmN/mNoPqR/sTuVwX/yZ0123")
            .expect("config");

        assert_eq!(config.segment, "gHiJkLmN");
        assert_eq!(config.bits, "0100");
        assert!(!config.from_host);

        let flags = config.flags.expect("flags");
        assert!(flags.bot_manager);
        assert!(!flags.force_secure);
        assert!(!flags.proof_of_work);
        assert!(!flags.akid);
    }

    #[test]
    fn an_odd_segment_carries_no_config() {
        assert!(
            read_config("https://www.maersk.com/pWSY7c1/2ib/AKfr/hFDsQoTHmWt/YwEfMkyRK8U/Y3g/AWJXAjJfBQ")
                .is_none()
        );
    }

    #[test]
    fn a_challenge_page_is_called_out() {
        let surface = discover(
            r#"<html><body><form action="/_sec/cp_challenge/ak-challenge-3-1.htm"></form></body></html>"#,
            "https://www.example.com/",
        );

        assert!(surface.challenge_page);
        assert!(!surface.is_protected());
    }
}
