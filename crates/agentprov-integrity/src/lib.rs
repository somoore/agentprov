//! agentprov-integrity — the signed tip that turns the keyless APCAP chain into
//! genuine tamper *evidence*.
//!
//! The capture format's per-frame hash chain proves only *consistency*: anyone
//! with file access can re-forge it. Authenticity comes from signing the final
//! frame's `frame_hash` (the chain tip) with an ed25519 key the agent process
//! cannot reach. Because the signature commits to the tip — which transitively
//! commits to every frame and to the frame *count* — a forger who edits or
//! truncates any frame produces a tip the signature no longer matches.
//!
//! Key handling mirrors the Go recorder: the ed25519 seed lives in the macOS
//! keychain (via the `security` CLI). NOTE — this raises the bar but is not an
//! airtight boundary: the keychain ACL trusts `/usr/bin/security`, so any
//! same-user process (including the captured agent, which can shell out) can
//! read the seed without a prompt. It defends against off-machine attackers and
//! casual tampering, not a same-user adversary with code execution. A hardware
//! key or a separate-uid signing daemon would close that gap (future work).
//! If the keychain is unavailable we fall back to an ephemeral key and say so —
//! still chained, just not non-repudiable. Honest degradation, never silent.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

pub const SEED_LEN: usize = 32;
pub const SIG_LEN: usize = 64;
pub const PUB_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    /// Seed loaded from / stored in the OS keychain — agent can't reach it.
    Keychain,
    /// Keychain unavailable; key generated for this run only. Weaker: the
    /// signature proves consistency for this process but isn't non-repudiable.
    Ephemeral,
}

pub struct Signing {
    key: SigningKey,
    pub source: KeySource,
}

impl Signing {
    /// Load the keychain-bound seed if present, else create one and store it.
    /// Falls back to an ephemeral key (reporting [`KeySource::Ephemeral`]) when
    /// the keychain can't be used — e.g. non-macOS, headless, or locked.
    pub fn load_or_create() -> Self {
        if let Some(seed) = keychain::get_seed() {
            return Self { key: SigningKey::from_bytes(&seed), source: KeySource::Keychain };
        }
        let mut seed = [0u8; SEED_LEN];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut seed);
        let key = SigningKey::from_bytes(&seed);
        if keychain::set_seed(&key.to_bytes()) {
            Self { key, source: KeySource::Keychain }
        } else {
            Self { key, source: KeySource::Ephemeral }
        }
    }

    /// Build a signer from an explicit seed (tests / non-keychain callers).
    pub fn from_seed(seed: [u8; SEED_LEN]) -> Self {
        Self { key: SigningKey::from_bytes(&seed), source: KeySource::Ephemeral }
    }

    pub fn public_key(&self) -> [u8; PUB_LEN] {
        self.key.verifying_key().to_bytes()
    }

    /// Sign a chain tip (the final frame's 32-byte `frame_hash`).
    pub fn sign_tip(&self, tip: &[u8; 32]) -> [u8; SIG_LEN] {
        self.key.sign(tip).to_bytes()
    }
}

/// The verifying (public) key bound in this machine's keychain, if present.
/// This is the *trusted anchor* for on-machine verification — it does NOT come
/// from the capture bundle, so an attacker who rewrites the bundled `.pub`
/// cannot fool a local verify.
pub fn keychain_public_key() -> Option<[u8; PUB_LEN]> {
    let seed = keychain::get_seed()?;
    Some(SigningKey::from_bytes(&seed).verifying_key().to_bytes())
}

#[derive(Debug, PartialEq, Eq)]
pub enum VerifyTip {
    Valid,
    BadSignature,
    BadKeyOrSig,
}

/// Verify a tip signature against a public key. `pub_hex` and `sig_hex` are the
/// hex strings written alongside the capture (`.pub` / `.sig`).
pub fn verify_tip(tip: &[u8; 32], pub_bytes: &[u8], sig_bytes: &[u8]) -> VerifyTip {
    let pk: [u8; PUB_LEN] = match pub_bytes.try_into() {
        Ok(b) => b,
        Err(_) => return VerifyTip::BadKeyOrSig,
    };
    let sg: [u8; SIG_LEN] = match sig_bytes.try_into() {
        Ok(b) => b,
        Err(_) => return VerifyTip::BadKeyOrSig,
    };
    let vk = match VerifyingKey::from_bytes(&pk) {
        Ok(v) => v,
        Err(_) => return VerifyTip::BadKeyOrSig,
    };
    match vk.verify(tip, &Signature::from_bytes(&sg)) {
        Ok(()) => VerifyTip::Valid,
        Err(_) => VerifyTip::BadSignature,
    }
}

pub fn to_hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter().fold(String::with_capacity(b.len() * 2), |mut s, byte| {
        let _ = write!(s, "{byte:02x}");
        s
    })
}

pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// macOS keychain seed storage via the `security` CLI — same mechanism as the
/// Go recorder, so no extra crate. On non-macOS the commands simply fail and we
/// fall back to ephemeral. ponytail: shelling out to `security` is the OS's own
/// supported API for this; a native Security.framework binding would add a big
/// dep for no behavioral gain in the trusted path.
mod keychain {
    use super::SEED_LEN;
    use std::process::Command;

    const SERVICE: &str = "agentprov-signing-key";
    const ACCOUNT: &str = "agentprov";

    pub fn get_seed() -> Option<[u8; SEED_LEN]> {
        let out = Command::new("security")
            .args(["find-generic-password", "-a", ACCOUNT, "-s", SERVICE, "-w"])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let hex = String::from_utf8_lossy(&out.stdout);
        let bytes = super::from_hex(hex.trim())?;
        bytes.try_into().ok()
    }

    pub fn set_seed(seed: &[u8; SEED_LEN]) -> bool {
        Command::new("security")
            .args([
                "add-generic-password", "-a", ACCOUNT, "-s", SERVICE,
                "-w", &super::to_hex(seed), "-U",
            ])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_then_verify_roundtrips() {
        let s = Signing::from_seed([7u8; 32]);
        let tip = [42u8; 32];
        let sig = s.sign_tip(&tip);
        assert_eq!(verify_tip(&tip, &s.public_key(), &sig), VerifyTip::Valid);
    }

    #[test]
    fn altered_tip_fails_verification() {
        // This is the property the keyless chain lacked: change the tip (i.e.
        // edit or truncate any frame, which changes the final frame_hash) and
        // the signature no longer validates.
        let s = Signing::from_seed([7u8; 32]);
        let sig = s.sign_tip(&[42u8; 32]);
        let mut forged_tip = [42u8; 32];
        forged_tip[0] ^= 0xff;
        assert_eq!(verify_tip(&forged_tip, &s.public_key(), &sig), VerifyTip::BadSignature);
    }

    #[test]
    fn wrong_key_fails() {
        let signer = Signing::from_seed([1u8; 32]);
        let other = Signing::from_seed([2u8; 32]);
        let tip = [9u8; 32];
        let sig = signer.sign_tip(&tip);
        assert_eq!(verify_tip(&tip, &other.public_key(), &sig), VerifyTip::BadSignature);
    }

    #[test]
    fn resign_attack_rejected_when_pinned_to_trusted_key() {
        // THE attack the thesis is about: an attacker re-forges the chain AND
        // re-signs the forged tip with their OWN fresh key, overwriting the
        // bundled .pub/.sig. Verifying against the *bundled* key would say VALID
        // (their key signs their tip). Verifying against the TRUSTED key (the
        // real recorder's, pinned out-of-band / from keychain) catches it.
        let trusted = Signing::from_seed([100u8; 32]); // the real recorder
        let attacker = Signing::from_seed([200u8; 32]); // fresh attacker key
        let forged_tip = [0xabu8; 32];
        let attacker_sig = attacker.sign_tip(&forged_tip);

        // Against the bundled (attacker) key, the forgery "verifies" — the hole.
        assert_eq!(
            verify_tip(&forged_tip, &attacker.public_key(), &attacker_sig),
            VerifyTip::Valid,
            "bundled-key verify is fooled — this is why we must pin"
        );
        // Against the trusted key, it's rejected. This is the fix.
        assert_eq!(
            verify_tip(&forged_tip, &trusted.public_key(), &attacker_sig),
            VerifyTip::BadSignature,
            "pinned-key verify rejects the re-signed forgery"
        );
    }

    #[test]
    fn hex_roundtrip() {
        let b = [0u8, 1, 254, 255, 16];
        assert_eq!(from_hex(&to_hex(&b)).unwrap(), b);
        assert!(from_hex("xyz").is_none());
        assert!(from_hex("abc").is_none()); // odd length
    }
}
