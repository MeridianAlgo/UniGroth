//! # Auth Circuit Trusted Setup
//!
//! Generates the proving key (`pk.bin`) and verifying key (`vk.bin`) for the
//! `AuthCircuit`. These artifacts are the public parameters of the zkSNARK and
//! must be produced once per deployment.
//!
//! ## Output files
//!
//! * `pk.bin` — proving key. Ship to the browser bundle (e.g. `public/pk.bin`).
//! * `vk.bin` — verifying key. Ship to the server (e.g. `server/keys/vk.bin`).
//!
//! ## Usage
//!
//! ```bash
//! cargo run --release --features auth-bin --bin auth_setup -- --out keys/
//! ```
//!
//! ## Security note
//!
//! The setup randomness (toxic waste) is drawn from the operating system's
//! CSPRNG and dropped when the process exits. Anyone who learns it can forge
//! proofs, so there is deliberately no deterministic or seeded mode. For a
//! production deployment, run a multi-party ceremony instead of a single machine.

use std::{
    fs,
    path::{Path, PathBuf},
};

use ark_bn254::{Bn254, Fr};
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use ark_std::rand::rngs::OsRng;

use unigroth::{auth::mimc_round_constants, auth::AuthCircuit, Groth16};

fn parse_args() -> PathBuf {
    let mut out_dir = PathBuf::from("keys");
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--out" => {
                out_dir = PathBuf::from(args.next().expect("--out requires a directory argument"));
            },
            "-h" | "--help" => {
                eprintln!("auth_setup --out <dir>");
                std::process::exit(0);
            },
            other => {
                eprintln!("unknown arg: {other}");
                std::process::exit(2);
            },
        }
    }
    out_dir
}

fn write_file<T: CanonicalSerialize>(path: &Path, value: &T) -> std::io::Result<usize> {
    let mut buf = Vec::new();
    value.serialize_compressed(&mut buf).expect("ark serialize");
    fs::write(path, &buf)?;
    Ok(buf.len())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = parse_args();
    fs::create_dir_all(&out_dir)?;

    let constants = mimc_round_constants::<Fr>();
    let empty = AuthCircuit::<Fr>::empty(constants);

    eprintln!("[auth_setup] generating Groth16 keys for AuthCircuit on BN254 ...");
    let started = std::time::Instant::now();
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(empty, &mut OsRng)?;
    eprintln!("[auth_setup] setup done in {:?}", started.elapsed());

    let pk_path = out_dir.join("pk.bin");
    let vk_path = out_dir.join("vk.bin");
    let pk_size = write_file(&pk_path, &pk)?;
    let vk_size = write_file(&vk_path, &vk)?;

    eprintln!(
        "[auth_setup] wrote {} ({} bytes)",
        pk_path.display(),
        pk_size
    );
    eprintln!(
        "[auth_setup] wrote {} ({} bytes)",
        vk_path.display(),
        vk_size
    );
    eprintln!("[auth_setup] OK");
    Ok(())
}
