//! Debug utility to inspect Ubique CBOR structure

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

const UBIQUE_DEVICE_RESPONSE_B64: &str = "o2d2ZXJzaW9uYzEuMGlkb2N1bWVudHOBo2dkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGxpc3N1ZXJTaWduZWSiam5hbWVTcGFjZXOhcW9yZy5pc28uMTgwMTMuNS4xgtgYWEOkAmZyYW5kb21QVt4N2bkRJRE0u7JYOmSmF2hkaWdlc3RJRABxZWxlbWVudElkZW50aWZpZXJrZmFtaWx5X25hbWVsZWxlbWVudFZhbHVlZFRFU1TYGFhApAJmcmFuZG9tUPrz0Bvn8F5iRBhZeUEG8BVoZGlnZXN0SUQBcWVsZW1lbnRJZGVudGlmaWVyamdpdmVuX25hbWVsZWxlbWVudFZhbHVlZFRFU1RqaXNzdWVyQXV0aISEQ6EBJqD2WEAFZ2b0zxWgSZHBvPKkZyZKk3fF3t0Eb0VGLlYTU1tGPhgEUJnPCb_L0PBgYzJqKkfCa5H5M4gzRvvtXvJKAHFkZXZpY2VTaWduZWSiam5hbWVTcGFjZXOgampkZXZpY2VBdXRooW9kZXZpY2VTaWduYXR1cmWEQ6EBJqBYQN7N5N0xK8ZQGXJj1g5TLlJ5HpF3YOXfV1pGLFH3r8Vv7Z9u0LHCGjJ3M0pRKvJUfGPPT0RvPKgYN1cKLZMHpGZzdGF0dXMA";

#[test]
fn debug_ubique_device_response() {
    println!("\n=== UBIQUE OID4VP DRAFT 18 CBOR DEBUG ===\n");

    let device_response_bytes = URL_SAFE_NO_PAD.decode(UBIQUE_DEVICE_RESPONSE_B64).unwrap();

    println!("Total bytes: {}", device_response_bytes.len());
    println!("First 100 bytes (hex):");
    for (i, chunk) in device_response_bytes.chunks(16).take(7).enumerate() {
        print!("{:08x}: ", i * 16);
        for byte in chunk {
            print!("{:02x} ", byte);
        }
        println!();
    }
    println!();

    // Try to parse as CBOR Value
    println!("=== Attempting CBOR parsing ===");
    match ciborium::de::from_reader::<ciborium::Value, _>(&device_response_bytes[..]) {
        Ok(value) => {
            println!("✓ Successfully parsed as CBOR Value\n");
            println!("=== Full Structure ===");
            println!("{:#?}\n", value);

            // Analyze issuerAuth structure specifically
            if let ciborium::Value::Map(root_map) = &value {
                for (k, v) in root_map {
                    if let ciborium::Value::Text(key) = k {
                        if key == "documents" {
                            if let ciborium::Value::Array(docs) = v {
                                for doc in docs {
                                    if let ciborium::Value::Map(doc_map) = doc {
                                        for (dk, dv) in doc_map {
                                            if let ciborium::Value::Text(doc_key) = dk {
                                                if doc_key == "issuerSigned" {
                                                    if let ciborium::Value::Map(issuer_map) = dv {
                                                        for (ik, iv) in issuer_map {
                                                            if let ciborium::Value::Text(
                                                                issuer_key,
                                                            ) = ik
                                                            {
                                                                if issuer_key == "issuerAuth" {
                                                                    println!("=== issuerAuth Structure ===");
                                                                    println!("{:#?}\n", iv);
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Err(e) => {
            println!("❌ Failed to parse as CBOR Value: {:?}\n", e);
        }
    }

    // Now try to deserialize as DeviceResponse
    println!("=== Attempting DeviceResponse deserialization ===");
    match ciborium::de::from_reader::<mdoc::DeviceResponse, _>(&device_response_bytes[..]) {
        Ok(_) => println!("✓ Successfully deserialized as DeviceResponse"),
        Err(e) => println!("❌ Failed to deserialize as DeviceResponse:\n{:?}", e),
    }
}
