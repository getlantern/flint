//! A startup self-check for the platform trust store (design §11).
//!
//! [`CertVerification::Roots`](crate::CertVerification::Roots) with an empty `roots_pem` verifies
//! against BoringSSL's *default paths*. On desktop those point at a real anchor set. On **Android and
//! iOS they point at nothing**, because those platforms keep their roots somewhere OpenSSL's path
//! convention cannot see, so an embedder must install a bundled set and point `SSL_CERT_FILE` at it.
//!
//! When an embedder forgets, every verified dial fails with `unable to get local issuer certificate` —
//! and that is **indistinguishable from a censored network** at the point of failure. Both look like
//! "nothing connects". Worse, the proxyless strategy search reads the failures as evidence about
//! strategies and keeps searching, so a local misconfiguration presents as a network that blocks
//! everything.
//!
//! [`check_default_trust_anchors`] turns that into a loud, specific error at init.
//!
//! # What this does and does not prove
//!
//! It asks **BoringSSL itself** which file, directory, and environment variables it will consult
//! (`X509_get_default_cert_file`/`_dir`/`_env`) and checks whether any of them actually yields
//! something, applying BoringSSL's own precedence rule: the environment path wins whenever the
//! variable is *present*, even when it is empty. Deriving both the paths and the rule from the library
//! rather than hardcoding them is the point — a hand-copied `/etc/ssl/certs`, or a guess that empty
//! means unset, would silently disagree with the BoringSSL actually linked in and pass a check it is
//! about to fail.
//!
//! It proves only that an anchor source **exists and is non-empty**. It does not parse the contents,
//! validate any certificate, or confirm that a *particular* root is present — so it catches the
//! misconfiguration it was built for (no anchors at all) and nothing subtler. A passing check does not
//! promise that verification will succeed; a failing one does promise it will not.
//!
//! It is deliberately **not** called automatically. Which anchors a process should trust is the
//! embedder's decision — a caller pinning `roots_pem` explicitly does not use the default paths at all
//! and should not be warned about them.

use std::ffi::CStr;
use std::path::{Path, PathBuf};

/// One place BoringSSL looks for anchors, and what is actually there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorSource {
    /// The path BoringSSL will read.
    pub path: PathBuf,
    /// Whether that path yields anything to load.
    pub usable: bool,
    /// Whether `path` came from the environment override rather than the compiled-in default.
    /// Distinguishes "the embedder configured this and it is wrong" from "nobody configured anything"
    /// — a much more useful thing to say in an error, and per-source so the message can name the
    /// variable actually at fault.
    pub from_env: bool,
}

/// Where BoringSSL will look for default trust anchors, and whether anything is there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustAnchorSources {
    /// The bundle file BoringSSL will read.
    pub file: AnchorSource,
    /// The hashed-anchor directory BoringSSL will read.
    pub dir: AnchorSource,
}

impl TrustAnchorSources {
    /// True if either source would give BoringSSL something to load. BoringSSL registers both lookups,
    /// so one live source is enough.
    pub fn any_usable(&self) -> bool {
        self.file.usable || self.dir.usable
    }

    /// True if either path came from an environment override.
    pub fn from_env(&self) -> bool {
        self.file.from_env || self.dir.from_env
    }
}

/// The trust store has no usable anchors, so every certificate-verified dial will fail.
#[derive(Debug, Clone, thiserror::Error)]
#[error(
    "no usable TLS trust anchors: {}, {}. {}",
    describe(&sources.file, "bundle", "SSL_CERT_FILE"),
    describe(&sources.dir, "directory", "SSL_CERT_DIR"),
    advice(sources)
)]
pub struct NoTrustAnchors {
    /// The paths that were checked, for diagnostics.
    pub sources: TrustAnchorSources,
}

fn describe(source: &AnchorSource, what: &str, var: &str) -> String {
    if source.usable {
        format!("{what} {} is usable", source.path.display())
    } else if source.from_env && source.path.as_os_str().is_empty() {
        // Worth naming rather than printing a blank path: an empty override is not a no-op, it
        // *suppresses* the compiled-in default, so this source loads nothing. Gated on `from_env`
        // because only an override can be empty — the compiled-in defaults are literal
        // concatenations (`OPENSSLDIR "/certs"`) — and a blank path from anywhere else would make
        // the "suppresses" claim false.
        format!("{var} is set to an empty value, which suppresses the built-in {what}")
    } else {
        format!("{what} {} is missing or empty", source.path.display())
    }
}

fn advice(sources: &TrustAnchorSources) -> &'static str {
    if sources.from_env() {
        "SSL_CERT_FILE/SSL_CERT_DIR is set but points at nothing usable — check the path the embedder installed"
    } else {
        "set SSL_CERT_FILE to a bundled CA bundle (Android and iOS keep their roots where these default paths cannot see them)"
    }
}

/// Check that a `CertVerification::Roots` dial with empty `roots_pem` will find trust anchors.
///
/// Call once at init. On `Err`, certificate verification cannot succeed for *any* peer, and reporting
/// that plainly is the whole point — otherwise it surfaces later as universal connection failure that
/// looks exactly like censorship.
///
/// Irrelevant to callers that pin `roots_pem`: those never consult the default paths.
///
/// See the module docs for the limits of what a pass proves.
pub fn check_default_trust_anchors() -> Result<TrustAnchorSources, NoTrustAnchors> {
    let sources = default_trust_anchor_sources();
    if sources.any_usable() {
        Ok(sources)
    } else {
        Err(NoTrustAnchors { sources })
    }
}

/// The paths BoringSSL will consult, resolved the same way it resolves them.
pub fn default_trust_anchor_sources() -> TrustAnchorSources {
    let (file, file_from_env) = resolve(
        std::env::var_os(boringssl_default_cert_file_env()),
        boringssl_default_cert_file(),
    );
    let (dir, dir_from_env) = resolve(
        std::env::var_os(boringssl_default_cert_dir_env()),
        boringssl_default_cert_dir(),
    );
    TrustAnchorSources {
        file: AnchorSource {
            usable: is_non_empty_file(&file),
            path: file,
            from_env: file_from_env,
        },
        dir: AnchorSource {
            usable: holds_an_entry(&dir),
            path: dir,
            from_env: dir_from_env,
        },
    }
}

/// The environment path if the variable is *present*, else the compiled-in default.
///
/// Presence, not content, is the rule — BoringSSL branches on `getenv() != NULL`, so `SSL_CERT_FILE=""`
/// still wins over the compiled-in default and then fails to load, leaving that source with zero
/// anchors. Treating empty as unset here would report the built-in path as the one in play and pass a
/// check BoringSSL is about to fail, which is the exact false pass this module exists to prevent.
/// Verified against boringssl `crypto/x509/by_file.c:88` and `by_dir.c:119` (boring-sys2 4.15.15).
///
/// Takes the looked-up value rather than reading the environment itself so the branch is testable
/// without mutating process-global state.
fn resolve(env_value: Option<std::ffi::OsString>, default: String) -> (PathBuf, bool) {
    // `var_os`, not `var`: it is `Some` for exactly the values `getenv` returns non-NULL for, including
    // the non-UTF-8 paths `var` would reject as an error and we would misread as unset.
    match env_value {
        Some(v) => (PathBuf::from(v), true),
        None => (PathBuf::from(default), false),
    }
}

/// A bundle is usable only if it has content: an empty file is a classic half-finished install, and
/// BoringSSL would load zero anchors from it just as if it were absent.
fn is_non_empty_file(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.len() > 0)
}

/// Likewise a hashed-anchor directory that exists but holds nothing.
///
/// Deliberately weaker than the file check, and worth being explicit about: BoringSSL never *lists*
/// this directory. It builds `<dir>/<subject-hash>.<n>` and opens that path directly
/// (`by_dir.c:321`), so nothing short of knowing every subject hash in advance could prove the
/// directory holds usable anchors. "Holds at least one readable entry" is a proxy for "somebody
/// populated this", which is the misconfiguration being caught — a directory of unrelated files
/// passes, and that is an accepted limit (see the module docs).
///
/// Requires an entry that actually *read*: `next().is_some()` would also accept a `Some(Err(_))`
/// from a directory whose contents cannot be enumerated, which is a false pass in a check whose
/// whole job is not producing them.
fn holds_an_entry(path: &Path) -> bool {
    std::fs::read_dir(path).is_ok_and(|mut entries| entries.any(|entry| entry.is_ok()))
}

// The four values below come from BoringSSL rather than being hardcoded, so they always match the
// build actually linked in. `CStr::from_ptr` is safe here: these return pointers to static string
// constants in libcrypto that outlive the call and are never mutated.
fn boringssl_default_cert_file() -> String {
    unsafe { cstr_to_string(boring_sys2::X509_get_default_cert_file()) }
}

fn boringssl_default_cert_dir() -> String {
    unsafe { cstr_to_string(boring_sys2::X509_get_default_cert_dir()) }
}

fn boringssl_default_cert_file_env() -> String {
    unsafe { cstr_to_string(boring_sys2::X509_get_default_cert_file_env()) }
}

fn boringssl_default_cert_dir_env() -> String {
    unsafe { cstr_to_string(boring_sys2::X509_get_default_cert_dir_env()) }
}

/// # Safety
/// `ptr` must be a non-null, NUL-terminated static string owned by libcrypto.
unsafe fn cstr_to_string(ptr: *const std::os::raw::c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    CStr::from_ptr(ptr).to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::*;

    #[test]
    fn the_paths_come_from_boringssl_not_from_us() {
        // The whole point of asking the library: a hardcoded path would drift from whatever this build
        // was compiled with. Assert they are real absolute paths rather than specific strings, which
        // would just re-hardcode the assumption inside the test.
        //
        // Against the compiled-in defaults directly, not through `default_trust_anchor_sources()`,
        // which layers the ambient environment on top: a runner with `SSL_CERT_DIR=` set would fail
        // `is_absolute` for a reason that says nothing about this code. Env resolution is covered by
        // `an_empty_env_var_suppresses_the_builtin_default`, on explicit values.
        let file = boringssl_default_cert_file();
        let dir = boringssl_default_cert_dir();
        assert!(Path::new(&file).is_absolute(), "{file:?}");
        assert!(Path::new(&dir).is_absolute(), "{dir:?}");
        assert!(!boringssl_default_cert_file_env().is_empty());
        assert!(!boringssl_default_cert_dir_env().is_empty());
    }

    #[test]
    fn an_empty_env_var_suppresses_the_builtin_default() {
        // BoringSSL branches on `getenv() != NULL`, so an empty value takes the env path and then
        // fails to load — it does *not* fall back. Reading it as "unset" would report the built-in
        // path as in play and pass a check that is about to fail, which is the whole failure mode.
        let (path, from_env) = resolve(Some(OsString::from("")), "/builtin/cert.pem".into());
        assert!(
            from_env,
            "an empty value is still a value BoringSSL will use"
        );
        assert_eq!(path, PathBuf::from(""), "and the built-in default is out");
        assert!(!is_non_empty_file(&path), "which loads no anchors");

        let (path, from_env) = resolve(None, "/builtin/cert.pem".into());
        assert!(!from_env);
        assert_eq!(path, PathBuf::from("/builtin/cert.pem"), "unset falls back");

        let (path, from_env) = resolve(Some(OsString::from("/env/cert.pem")), "/builtin".into());
        assert!(from_env);
        assert_eq!(path, PathBuf::from("/env/cert.pem"));
    }

    #[test]
    fn an_empty_file_is_not_a_usable_bundle() {
        // The half-finished install: the embedder created the file but never wrote the anchors, so
        // BoringSSL loads nothing from it — exactly as if it were absent.
        let dir = std::env::temp_dir().join("flint-anchors-test-empty");
        let _ = std::fs::create_dir_all(&dir);
        let empty = dir.join("empty.pem");
        std::fs::write(&empty, b"").unwrap();
        assert!(!is_non_empty_file(&empty));

        std::fs::write(&empty, b"-----BEGIN CERTIFICATE-----").unwrap();
        assert!(is_non_empty_file(&empty));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_or_empty_directory_is_not_usable() {
        let missing = std::env::temp_dir().join("flint-anchors-test-does-not-exist");
        let _ = std::fs::remove_dir_all(&missing);
        assert!(!holds_an_entry(&missing));

        std::fs::create_dir_all(&missing).unwrap();
        assert!(
            !holds_an_entry(&missing),
            "an empty directory holds no anchors"
        );
        std::fs::write(missing.join("anchor.0"), b"x").unwrap();
        assert!(holds_an_entry(&missing));
        let _ = std::fs::remove_dir_all(&missing);
    }

    #[test]
    fn the_error_says_what_to_do_about_it() {
        // A misconfigured embedder reads this string at 3am; it has to name the paths *and* the fix.
        let at = |p: &str| AnchorSource {
            path: PathBuf::from(p),
            usable: false,
            from_env: false,
        };
        let unset = NoTrustAnchors {
            sources: TrustAnchorSources {
                file: at("/nope/cert.pem"),
                dir: at("/nope/certs"),
            },
        };
        let msg = unset.to_string();
        assert!(
            msg.contains("/nope/cert.pem") && msg.contains("/nope/certs"),
            "{msg}"
        );
        assert!(msg.contains("SSL_CERT_FILE"), "{msg}");

        // And it distinguishes "configured, but wrong" from "never configured" — different bugs, and
        // telling an embedder to set a variable they already set would send them the wrong way.
        let misconfigured = NoTrustAnchors {
            sources: TrustAnchorSources {
                file: AnchorSource {
                    from_env: true,
                    ..at("/nope/cert.pem")
                },
                dir: at("/nope/certs"),
            },
        };
        assert!(
            misconfigured
                .to_string()
                .contains("points at nothing usable"),
            "{misconfigured}"
        );

        // An empty override would otherwise print as a blank path — say what it actually did, and name
        // the variable that did it, since only one of the two may be at fault.
        let blank = NoTrustAnchors {
            sources: TrustAnchorSources {
                file: AnchorSource {
                    path: PathBuf::new(),
                    usable: false,
                    from_env: true,
                },
                dir: at("/etc/ssl/certs"),
            },
        };
        let msg = blank.to_string();
        assert!(
            msg.contains("SSL_CERT_FILE is set to an empty value"),
            "{msg}"
        );
        assert!(
            !msg.contains("SSL_CERT_DIR is set to an empty value"),
            "the untouched source must not be blamed: {msg}"
        );

        // A blank path that did *not* come from an override cannot have suppressed anything — the
        // compiled-in defaults are literal concatenations and are never empty — so fall back to
        // neutral wording rather than asserting a cause that did not happen.
        let blank_default = NoTrustAnchors {
            sources: TrustAnchorSources {
                file: at(""),
                dir: at(""),
            },
        };
        assert!(
            !blank_default.to_string().contains("suppresses"),
            "{blank_default}"
        );
    }
}
