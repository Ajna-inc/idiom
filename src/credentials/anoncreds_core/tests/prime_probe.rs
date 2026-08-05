//! Isolates the CL prime-`e` generation cost — the per-credential prime that
//! dominates create_credential — to size the win from pre-generating primes.
use anoncreds_clsignatures::bn::BigNumber;
use std::time::Instant;

#[test]
fn profile_prime_e_generation() {
    // LARGE_E_START = 596, LARGE_E_END_RANGE = 119 (from clsignatures constants)
    for _ in 0..5 {
        let _ = BigNumber::generate_prime_in_range(596, 119).unwrap();
    }
    let n = 200usize;
    let t = Instant::now();
    for _ in 0..n {
        let _e = BigNumber::generate_prime_in_range(596, 119).unwrap();
    }
    let ms = t.elapsed().as_secs_f64() * 1000.0 / n as f64;
    println!("\n  CL prime-e generation: {ms:.2} ms/prime   (of ~25.4 ms/sign)\n");
}
