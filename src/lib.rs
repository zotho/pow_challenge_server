use std::{
    io::Write,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use sha2::{Digest, Sha256};

pub const ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 3000);

pub fn verify_proof(zero_count: usize, input: &str, postfix: u32) -> bool {
    let zeros_bytes = [0].repeat(zero_count / 2);
    let zeros = "0".repeat(zero_count);

    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.write_fmt(format_args!("{postfix}")).unwrap();
    let result: &[u8] = &hasher.finalize();

    // Check for faster condition first
    let cond_bytes = result.starts_with(&zeros_bytes);
    if !cond_bytes {
        return false;
    }

    let encoded_hash = hex::encode(result);
    encoded_hash.starts_with(&zeros)
}

pub fn solve_challenge(zero_count: usize, input: &str) -> u32 {
    let zeros_bytes = [0].repeat(zero_count / 2);
    let zeros = "0".repeat(zero_count);
    let mut postfix: u32 = 0;

    loop {
        postfix = postfix.checked_add(1).unwrap();

        let mut hasher = Sha256::new();
        hasher.update(input);
        hasher.write_fmt(format_args!("{postfix}")).unwrap();
        let result: &[u8] = &hasher.finalize();

        // Check for faster condition first
        let cond_bytes = result.starts_with(&zeros_bytes);
        if !cond_bytes {
            continue;
        }

        let encoded_hash = hex::encode(result);
        let cond_hex = encoded_hash.starts_with(&zeros);

        if cond_hex {
            return postfix;
        }
    }
}
