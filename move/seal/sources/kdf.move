module seal::kdf;

use sui::{bls12381::{G1, G2, GT}, group_ops::Element, hmac::hmac_sha3_256};

public(package) fun kdf(
    input: &Element<GT>,
    nonce: &Element<G2>,
    gid: &Element<G1>,
    info: &vector<u8>,
): vector<u8> {
    let mut bytes = *input.bytes();
    bytes.append(*nonce.bytes());
    bytes.append(*gid.bytes());

    hkdf_sha3_256(
        &bytes,
        &x"0000000000000000000000000000000000000000000000000000000000000000",
        info,
    )
}

// Fixed to 32 bytes. Must give non-empty salt.
fun hkdf_sha3_256(ikm: &vector<u8>, salt: &vector<u8>, info: &vector<u8>): vector<u8> {
    assert!(!salt.is_empty());
    let mut t = *info;
    t.push_back(1);
    hmac_sha3_256(&hmac_sha3_256(salt, ikm), &t)
}
