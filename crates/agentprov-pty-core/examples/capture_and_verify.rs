//! End-to-end library example: capture a command under a PTY, then verify the
//! signed tamper-evident chain.
//!
//!   cargo run -p agentprov-pty-core --example capture_and_verify
//!
//! This is the whole trusted path in ~30 lines: capture (pty-core) → verify
//! (capture-format) → sign + authenticate the tip (integrity).

use agentprov_capture_format::{verify, FrameType};
use agentprov_integrity::{to_hex, verify_tip, Signing, VerifyTip};
use agentprov_pty_core::CaptureSession;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out = std::env::temp_dir().join("agentprov-example.apcap");

    // 1. Capture `/bin/sh -c 'printf ...'` under a PTY.
    let result = CaptureSession::new(
        "/bin/sh".into(),
        vec!["-c".into(), "printf 'hello from agentprov\\n'".into()],
        out.clone(),
    )
    .run()?;
    println!("captured {} frames (exit {})", result.frames_written, result.exit_code);

    // 2. Verify the hash chain; collect the tip + the recorded output.
    let bytes = std::fs::read(&out)?;
    let mut tip = [0u8; 32];
    let mut output = Vec::new();
    let n = verify(&bytes[..], |f| {
        tip = f.frame_hash;
        if f.frame_type == FrameType::PtyOutput {
            output.extend_from_slice(&f.payload);
        }
    })?;
    println!("chain verifies: {n} frames, {} output bytes", output.len());

    // 3. Sign the tip, then authenticate it against the signer's own key.
    let signer = Signing::load_or_create();
    let sig = signer.sign_tip(&tip);
    match verify_tip(&tip, &signer.public_key(), &sig) {
        VerifyTip::Valid => println!("SIGNATURE VALID — tip {}", &to_hex(&tip)[..16]),
        _ => println!("signature did not verify"),
    }

    let _ = std::fs::remove_file(&out);
    Ok(())
}
