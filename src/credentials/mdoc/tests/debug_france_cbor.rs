//! Debug utility to inspect France playground CBOR structure

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::prelude::*;

const FRANCE_DEVICE_RESPONSE_B64: &str = "o2d2ZXJzaW9uYzEuMGlkb2N1bWVudHOBo2dkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGxpc3N1ZXJTaWduZWSiam5hbWVTcGFjZXOhcW9yZy5pc28uMTgwMTMuNS4xhdgYWEOkAmZyYW5kb21QQPvU8hb-EILkpWAhyKfTOnFoZGlnZXN0SUQBcWVsZW1lbnRJZGVudGlmaWVya2ZhbWlseV9uYW1lbGVsZW1lbnRWYWx1ZWVTTUlUSOAYWEOkAmZyYW5kb21Q5LRBcK5mYTDPVfmWe4CQ5GhkaWdlc3RJRAJxZWxlbWVudElkZW50aWZpZXJqZ2l2ZW5fbmFtZWxlbGVtZW50VmFsdWVjSk9O2BhYQKQCZnJhbmRvbVDEw6p1d0nX_IJ2dKwJgX5qaGRpZ2VzdElEA3FlbGVtZW50SWRlbnRpZmllcmpiaXJ0aF9kYXRlbGVsZW1lbnRWYWx1ZWoyMDAwLTAxLTAx2BhYQ6QCZnJhbmRvbVCS0SLqxPeoDx-fXRLh_QfDaGRpZ2VzdElEBHFlbGVtZW50SWRlbnRpZmllcmlpc3N1ZV9kYXRlbGVsZW1lbnRWYWx1ZWoyMDIxLTA5LTE02BhYRKQCZnJhbmRvbVAmODdKqiSdjCp_cL2IG0q9aGRpZ2VzdElEBXFlbGVtZW50SWRlbnRpZmllcmtleHBpcnlfZGF0ZWxlbGVtZW50VmFsdWVqMjAyMS0xMC0xNGppc3N1ZXJBdXRohEOhASag9lhA_5rCVHqGt-xUKT2L0xB1IvmDdKJLHk7X_Ew3WdVDvbJ3u-4eQOtABUxNyBWsQ2b7fN0VaJVZ0qVw-9KQAHFkZXZpY2VTaWduZWSiam5hbWVTcGFjZXOgampkZXZpY2VBdXRooW9kZXZpY2VTaWduYXR1cmWEQ6EBJqBYQKHj4I0dNYb0nKEGT9gBLXGpM8sVJqZVRv7OKlDKYKl8LYTwJr0dOQXBkKBPfm3GOtPJVqfP4QCxCfW7pWS0rGZzdGF0dXMA";

#[test]
fn debug_france_device_response() {
    println!("\n=== FRANCE PLAYGROUND OID4VP DRAFT 18 CBOR DEBUG ===\n");

    let device_response_bytes = URL_SAFE_NO_PAD.decode(FRANCE_DEVICE_RESPONSE_B64).unwrap();

    println!("Total bytes: {}", device_response_bytes.len());
    println!(
        "First 50 bytes (hex): {:02x?}\n",
        &device_response_bytes[..50.min(device_response_bytes.len())]
    );
    println!(
        "Last 50 bytes (hex): {:02x?}\n",
        &device_response_bytes[device_response_bytes.len().saturating_sub(50)..]
    );

    // Look for CBOR simple values (0xE0-0xFF in major type 7)
    println!("\n=== Searching for CBOR Simple Values ===");
    for (i, byte) in device_response_bytes.iter().enumerate() {
        if *byte >= 0xE0 {
            println!(
                "Found potential simple value at offset {}: 0x{:02x}",
                i, byte
            );
            if i > 5 {
                println!(
                    "  Context (5 bytes before): {:02x?}",
                    &device_response_bytes[i.saturating_sub(5)..=i]
                );
            }
            if i + 5 < device_response_bytes.len() {
                println!(
                    "  Context (5 bytes after): {:02x?}",
                    &device_response_bytes[i..i + 5.min(device_response_bytes.len() - i)]
                );
            }
        }
    }
    println!();
}
