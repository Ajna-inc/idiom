//! Debug test to see the actual CBOR structure of Google's device response

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ciborium::Value;

#[test]
fn debug_google_device_response() {
    const DEVICE_RESPONSE_B64: &str = "o2d2ZXJzaW9uYzEuMGlkb2N1bWVudHOBo2dkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGxpc3N1ZXJTaWduZWSiam5hbWVTcGFjZXOhcW9yZy5pc28uMTgwMTMuNS4xgtgYWFSkaGRpZ2VzdElEAGZyYW5kb21Qh2ub69pgXPJIlpOYhAJYX3FlbGVtZW50SWRlbnRpZmllcmtmYW1pbHlfbmFtZWxlbGVtZW50VmFsdWVlU21pdGjYGFhRpGhkaWdlc3RJRAFmcmFuZG9tUJyft6VAh5wxzh_YqEvXtPBxZWxlbWVudElkZW50aWZpZXJqZ2l2ZW5fbmFtZWxlbGVtZW50VmFsdWVjSm9uamlzc3VlckF1dGiEQ6EBJqEYIVkCxDCCAsAwggJnoAMCAQICFB5_GzKtTzTv5LDMB7ew4zOnCxhNMAoGCCqGSM49BAMCMHkxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1Nb3VudGFpbiBWaWV3MRwwGgYDVQQKDBNEaWdpdGFsIENyZWRlbnRpYWxzMR8wHQYDVQQDDBZkaWdpdGFsY3JlZGVudGlhbHMuZGV2MB4XDTI1MDIxOTIzMzAxOFoXDTI2MDIxOTIzMzAxOFoweTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxHDAaBgNVBAoME0RpZ2l0YWwgQ3JlZGVudGlhbHMxHzAdBgNVBAMMFmRpZ2l0YWxjcmVkZW50aWFscy5kZXYwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATreTYr4tfzl8NQBH2D4eNiLONVazYPamjHWLsN3Gr4bAmvml1dDZk5dhLDWieRlpjKAA_IpMABbM2ISHjYBeNpo4HMMIHJMB8GA1UdIwQYMBaAFKJP9InZfEbobqOG2UdIzsy-3M_1MB0GA1UdDgQWBBTf_mpaEunAYsS8mKcl0tlw93pgKDA0BgNVHR8ELTArMCmgJ6AlhiNodHRwczovL2RpZ2l0YWwtY3JlZGVudGlhbHMuZGV2L2NybDAqBgNVHRIEIzAhhh9odHRwczovL2RpZ2l0YWwtY3JlZGVudGlhbHMuZGV2MA4GA1UdDwEB_wQEAwIHgDAVBgNVHSUBAf8ECzAJBgcogYxdBQECMAoGCCqGSM49BAMCA0cAMEQCIGHFy_V8weN78uCxM9ofIDEEXXCbWiEUDnpoMJvLB0LnAiBwr6LhxJv7p4wVzAnlGe0Ef8pqYxshyE8NufwfR_ULAlkButgYWQG1pmd2ZXJzaW9uYzEuMG9kaWdlc3RBbGdvcml0aG1nU0hBLTI1Nmdkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGx2YWx1ZURpZ2VzdHOhcW9yZy5pc28uMTgwMTMuNS4xowBYIF4np1s8h5zq4R447fmweHJCW6Nd0X9qIlFVmdBckcxQAVgg5epO0W1CanUYkN3my72qMFM_NnUTmlUcXuYpkzhCK8ICWCAA5AsOZa7MqBIVYBoG7kGirGgnXgj2gW5ZN1MtEKKJvm1kZXZpY2VLZXlJbmZvoWlkZXZpY2VLZXmkAQIgASFYIITrf6TK84s7dF1jir4ZcQ3mnpOnnBLlOgI_rhbTqBfeIlgg4-d5b1QVCsUwKg3UoYLAn22ttZofjKqX6ajH0Jq7TeJsdmFsaWRpdHlJbmZvo2ZzaWduZWTAeBsyMDI1LTAyLTE5VDIzOjM2OjU4LjIxMDM5MVppdmFsaWRGcm9twHgbMjAyNS0wMi0xOVQyMzozNjo1OC4yMTAzOTlaanZhbGlkVW50aWzAeBsyMDM1LTAyLTA3VDIzOjM2OjU4LjIxMDM5OVpYQH2YP3brP6bfJDJO_FoaPUWwB5LtpYVYKChulL-3yQesOMekny68Gt-G9J3rEZMw7MUI64Y35nWJMqIF_9xB9zFsZGV2aWNlU2lnbmVkompuYW1lU3BhY2Vz2BhBoGpkZXZpY2VBdXRooW9kZXZpY2VTaWduYXR1cmWEQ6EBJqD2WEDHs4neVqi52ED9ea7fj6Skeu-mtHZRwJwN5jAY7sfT7wL-1iVNIIktp6lC4Z_fRoOukVgQn0t1CKrnyEOFe45yZnN0YXR1cwA";

    // Decode from base64
    let device_response_bytes = URL_SAFE_NO_PAD.decode(DEVICE_RESPONSE_B64).unwrap();

    println!("Total bytes: {}", device_response_bytes.len());
    println!(
        "First 20 bytes (hex): {:02x?}",
        &device_response_bytes[..20]
    );

    // Decode as CBOR Value to see structure
    let value: Value = ciborium::de::from_reader(&device_response_bytes[..]).unwrap();

    println!("\n=== Full CBOR Structure ===");
    println!("{:#?}", value);

    // Try to extract specific fields
    if let Value::Map(map) = &value {
        for (k, v) in map {
            if let Value::Text(key) = k {
                println!("\n=== Field: {} ===", key);
                match key.as_str() {
                    "version" => println!("version: {:?}", v),
                    "documents" => {
                        if let Value::Array(docs) = v {
                            println!("documents array length: {}", docs.len());
                            if let Some(first_doc) = docs.first() {
                                println!("First document type: {:?}", get_type_name(first_doc));
                                if let Value::Map(doc_map) = first_doc {
                                    for (dk, dv) in doc_map {
                                        if let Value::Text(doc_key) = dk {
                                            println!(
                                                "  Document.{}: type={}",
                                                doc_key,
                                                get_type_name(dv)
                                            );

                                            if doc_key == "issuerSigned" {
                                                if let Value::Map(issuer_map) = dv {
                                                    for (ik, iv) in issuer_map {
                                                        if let Value::Text(issuer_key) = ik {
                                                            println!(
                                                                "    IssuerSigned.{}: type={}",
                                                                issuer_key,
                                                                get_type_name(iv)
                                                            );
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
                    "status" => println!("status type: {}, value: {:?}", get_type_name(v), v),
                    _ => {}
                }
            }
        }
    }
}

fn get_type_name(v: &Value) -> &'static str {
    match v {
        Value::Integer(_) => "Integer",
        Value::Bytes(_) => "Bytes",
        Value::Float(_) => "Float",
        Value::Text(_) => "Text",
        Value::Bool(_) => "Bool",
        Value::Null => "Null",
        Value::Tag(_, _) => "Tag",
        Value::Array(_) => "Array",
        Value::Map(_) => "Map",
        _ => "Unknown",
    }
}
