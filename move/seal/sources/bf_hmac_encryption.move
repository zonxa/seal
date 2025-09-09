// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Implementation of decryption for Seal using Boneh-Franklin over BLS12-381 as KEM and Hmac256Ctr as DEM.
/// Refer usage at docs https://seal-docs.wal.app/UsingSeal/#on-chain-decryption
module seal::bf_hmac_encryption;

use seal::{hmac256ctr, kdf::{hash_to_g1_with_dst, kdf}, polynomial::{interpolate_all, Polynomial}};
use std::{hash::sha3_256, option::none};
use sui::{
    bls12381::{
        G1,
        G2,
        Scalar,
        pairing,
        g2_from_bytes,
        g2_generator,
        scalar_from_bytes,
        g1_mul,
        g2_mul
    },
    group_ops::Element
};

const DST_DERIVE_KEY: vector<u8> = b"SUI-SEAL-IBE-BLS12381-H3-00";

public struct EncryptedObject has copy, drop, store {
    package_id: address,
    id: vector<u8>,
    indices: vector<u8>,
    services: vector<address>,
    threshold: u8,
    nonce: Element<G2>,
    encrypted_shares: vector<vector<u8>>,
    encrypted_randomness: vector<u8>,
    blob: vector<u8>,
    aad: Option<vector<u8>>,
    mac: vector<u8>,
}

public struct VerifiedDerivedKey has drop, store {
    derived_key: Element<G1>,
    package_id: address,
    id: vector<u8>,
    key_server: ID,
}

public struct PublicKey has drop {
    key_server: ID,
    pk: Element<G2>,
}

/// Creates PublicKey from key server ID and public key bytes.
public fun new_public_key(key_server_id: ID, pk_bytes: vector<u8>): PublicKey {
    PublicKey {
        key_server: key_server_id,
        pk: g2_from_bytes(&pk_bytes),
    }
}

#[test_only]
public fun get_public_key(key_server: &seal::key_server::KeyServer): PublicKey {
    PublicKey {
        key_server: object::id(key_server),
        pk: key_server.pk_as_bf_bls12381(),
    }
}

/// Decrypts an encrypted object using the given verified derived keys.
///
/// Call `verify_derived_keys` to verify derived keys before calling this function.
///
/// Aborts if there are not enough verified derived keys.
/// Aborts if any of the key servers are not among the key servers found in the encrypted object.
///
/// If the decryption fails, e.g. the AAD or MAC is invalid, the function returns `none`.
///
/// For now, this only supports unweighted key servers, so even if the encrypted object has weighted key servers,
/// each derived key contributes only 1 towards the threshold.
#[allow(unused_variable)]
public fun decrypt(
    encrypted_object: &EncryptedObject,
    verified_derived_keys: &vector<VerifiedDerivedKey>,
    public_keys: &vector<PublicKey>,
): Option<vector<u8>> {
    let EncryptedObject {
        threshold,
        package_id,
        id,
        nonce,
        blob,
        mac,
        aad,
        indices,
        encrypted_shares,
        encrypted_randomness,
        services,
    } = encrypted_object;
    assert!(verified_derived_keys.length() >= *threshold as u64);
    assert!(verified_derived_keys.all!(|vdk| vdk.package_id == *package_id && vdk.id == *id));
    assert_all_unique(&verified_derived_keys.map_ref!(|vdk| vdk.key_server));

    // Verify that the public keys are from the key servers in the encrypted object and in the same order.
    let public_keys = public_keys.zip_map_ref!(services, |pk, addr| {
        assert!(pk.key_server.to_address() == addr);
        pk.pk
    });

    // Find the indices of the key servers corresponding to the derived keys.
    // This aborts if one of the given derived keys is not from a key server in the encrypted object.
    let given_indices = verified_derived_keys.map_ref!(
        |vdk| services.find_index!(|service| vdk.key_server.to_address() == service).extract(),
    );

    // Decrypt shares.
    let decrypted_shares = decrypt_shares_with_derived_keys(
        &given_indices,
        verified_derived_keys,
        encrypted_object,
    );

    // Interpolate polynomials from the decrypted shares.
    let polynomials = interpolate_all(&given_indices.map!(|i| indices[i]), &decrypted_shares);

    // Compute base key and derive keys for the randomness and DEM.
    let base_key = polynomials.map_ref!(|p| p.get_constant_term());
    let randomness_key = derive_key(KeyPurpose::EncryptedRandomness, &base_key, encrypted_object);
    let dem_key = derive_key(KeyPurpose::DEM, &base_key, encrypted_object);

    // Decrypt the randomness
    let randomness = decrypt_randomness(
        &randomness_key,
        encrypted_randomness,
    );
    if (randomness.is_none()) {
        return none()
    };
    let randomness = randomness.destroy_some();

    // Use the randomness to verify the nonce.
    if (!verify_nonce(&randomness, &encrypted_object.nonce)) {
        return none()
    };

    // Now, all shares can be decrypted using the randomness and the public keys.
    let all_shares = decrypt_all_shares_with_randomness(
        &randomness,
        encrypted_object,
        &public_keys,
    );

    // Verify the consistency of the shares, eg. that they are all consistent with the polynomial interpolated from the shares decrypted from the given keys.
    if (
        all_shares
            .zip_map_ref!(indices, |share, index| verify_share(&polynomials, share, *index))
            .any!(|verified| !*verified)
    ) {
        return none()
    };

    // Decrypt the blob.
    hmac256ctr::decrypt(
        blob,
        mac,
        &aad.get_with_default(vector[]),
        &dem_key,
    )
}

fun decrypt_randomness(
    randomness_key: &vector<u8>,
    encrypted_randomness: &vector<u8>,
): Option<Element<Scalar>> {
    safe_scalar_from_bytes(
        &xor(
            encrypted_randomness,
            randomness_key,
        ),
    )
}

/// The order of the scalar field for BLS12-381.
const SCALAR_FIELD_ORDER: u256 =
    52435875175126190479447740508185965837690552500527637822603658699938581184513u256;

const SCALAR_BYTE_LENGTH: u64 = 32;

/// Converts big-endian bytes to a scalar, returning none if the bytes are not a valid scalar.
fun safe_scalar_from_bytes(be_bytes: &vector<u8>): Option<Element<Scalar>> {
    if (be_bytes.length() != SCALAR_BYTE_LENGTH) {
        return none()
    };
    // bcs peels in little-endian order, but the scalar is in big-endian order
    let mut le_bytes = *be_bytes;
    le_bytes.reverse();
    let as_integer = sui::bcs::new(le_bytes).peel_u256();
    if (as_integer >= SCALAR_FIELD_ORDER) {
        return none()
    };
    option::some(scalar_from_bytes(be_bytes))
}

fun verify_nonce(randomness: &Element<Scalar>, nonce: &Element<G2>): bool {
    nonce == g2_mul(randomness, &g2_generator())
}

fun verify_share(polynomials: &vector<Polynomial>, share: &vector<u8>, index: u8): bool {
    polynomials.zip_map_ref!(share, |p, s| p.evaluate(index) == s).all!(|verified| *verified)
}

/// Decrypt the given shares with the derived keys.
/// Panics if the number of indices does not match the number of derived keys.
fun decrypt_shares_with_derived_keys(
    indices: &vector<u64>,
    derived_keys: &vector<VerifiedDerivedKey>,
    encrypted_object: &EncryptedObject,
): vector<vector<u8>> {
    let gid = hash_to_g1_with_dst(
        &create_full_id(encrypted_object.package_id, encrypted_object.id),
    );
    indices.zip_map_ref!(derived_keys, |i, vdk| {
        xor(
            &encrypted_object.encrypted_shares[*i],
            &kdf(
                &pairing(&vdk.derived_key, &encrypted_object.nonce),
                &encrypted_object.nonce,
                &gid,
                encrypted_object.services[*i],
                encrypted_object.indices[*i],
            ),
        )
    })
}

/// Decrypts shares with the given randomness.
fun decrypt_all_shares_with_randomness(
    randomness: &Element<Scalar>,
    encrypted_object: &EncryptedObject,
    public_keys: &vector<Element<G2>>,
): (vector<vector<u8>>) {
    let n = encrypted_object.indices.length();
    assert!(n == public_keys.length());
    let gid = hash_to_g1_with_dst(
        &create_full_id(encrypted_object.package_id, encrypted_object.id),
    );
    let gid_r = g1_mul(randomness, &gid);
    vector::tabulate!(n, |i| {
        xor(
            &encrypted_object.encrypted_shares[i],
            &kdf(
                &pairing(&gid_r, &public_keys[i]),
                &encrypted_object.nonce,
                &gid,
                encrypted_object.services[i],
                encrypted_object.indices[i],
            ),
        )
    })
}

fun create_full_id(package_id: address, id: vector<u8>): vector<u8> {
    let mut full_id = vector::empty();
    full_id.append(package_id.to_bytes());
    full_id.append(id);
    full_id
}

/// An enum representing the different purposes of the derived key.
public enum KeyPurpose {
    EncryptedRandomness,
    DEM,
}

/// Derives a key for a specific purpose from the base key.
fun derive_key(
    purpose: KeyPurpose,
    base_key: &vector<u8>,
    encrypted_object: &EncryptedObject,
): vector<u8> {
    let tag = match (purpose) {
        KeyPurpose::EncryptedRandomness => vector[0],
        KeyPurpose::DEM => vector[1],
    };
    let mut bytes = DST_DERIVE_KEY;
    bytes.append(*base_key);
    bytes.append(tag);
    bytes.push_back(encrypted_object.threshold);
    encrypted_object.encrypted_shares.do_ref!(|share| bytes.append(*share));
    encrypted_object.services.do_ref!(|key_server| bytes.append((*key_server).to_bytes()));
    sha3_256(bytes)
}

fun xor(a: &vector<u8>, b: &vector<u8>): vector<u8> {
    assert!(a.length() == b.length());
    a.zip_map_ref!(b, |a, b| *a ^ *b)
}

/// Returns a vector of `VerifiedDerivedKey`s, asserting that all derived_keys are valid for the given full ID and key servers.
/// Aborts if the number of key servers does not match the number of derived keys.
public fun verify_derived_keys(
    derived_keys: &vector<Element<G1>>,
    package_id: address,
    id: vector<u8>,
    public_keys: &vector<PublicKey>,
): vector<VerifiedDerivedKey> {
    assert!(public_keys.length() == derived_keys.length());
    let gid = hash_to_g1_with_dst(&create_full_id(package_id, id));
    public_keys.zip_map_ref!(derived_keys, |pk, derived_key| {
        assert!(verify_derived_key(derived_key, &gid, &pk.pk));
        VerifiedDerivedKey {
            derived_key: *derived_key,
            key_server: pk.key_server,
            package_id,
            id,
        }
    })
}

fun verify_derived_key(
    derived_key: &Element<G1>,
    gid: &Element<G1>,
    public_key: &Element<G2>,
): bool {
    pairing(derived_key, &g2_generator()) == pairing(gid, public_key)
}

fun assert_all_unique<T: drop + copy>(items: &vector<T>) {
    let mut seen = vector::empty();
    items.do_ref!(|item| {
        assert!(seen.find_index!(|i| i == item).is_none());
        seen.push_back(*item);
    })
}

/// Deserialize a BCS encoded EncryptedObject.
/// Fails if the version is not 0.
/// Fails if the object is not a valid EncryptedObject.
/// Fails if the encryption type is not Hmac256Ctr.
/// Fails if the KEM type is not Boneh-Franklin over BLS12-381.
public fun parse_encrypted_object(object: vector<u8>): EncryptedObject {
    let mut bcs = sui::bcs::new(object);

    let version = bcs.peel_u8();
    assert!(version == 0);

    let package_id = bcs.peel_address();
    let id = bcs.peel_vec_u8();

    // services is a vector of tuples of the form (address, u8).
    let mut services: vector<address> = vector::empty();
    let indices = bcs.peel_vec!(|service| {
        services.push_back(service.peel_address());
        service.peel_u8()
    });
    assert!(services.length() == indices.length());
    assert_all_unique(&indices);
    let threshold = bcs.peel_u8();
    assert!(threshold > 0 && threshold <= indices.length() as u8);

    let ibe_type = bcs.peel_enum_tag();
    assert!(ibe_type == 0);

    // nonce is an G2 element, which is 96 bytes.
    let nonce_bytes = peel_tuple_u8(&mut bcs, 96);
    let nonce = g2_from_bytes(&nonce_bytes);

    // Shares are 32 bytes.
    let encrypted_shares = bcs.peel_vec!(|share_bcs| peel_tuple_u8(share_bcs, 32));
    assert!(encrypted_shares.length() == indices.length());

    // Encrypted randomness is 32 bytes.
    let encrypted_randomness = peel_tuple_u8(&mut bcs, 32);

    // Move only supports Hmac256Ctr mode.
    let encryption_type = bcs.peel_enum_tag();
    assert!(encryption_type == 1);

    let blob = bcs.peel_vec_u8();
    let aad = bcs.peel_option!(|aad_bcs| aad_bcs.peel_vec_u8());

    // MAC is 32 bytes.
    let mac = peel_tuple_u8(&mut bcs, 32);

    EncryptedObject {
        package_id,
        id,
        services,
        indices,
        threshold,
        nonce,
        encrypted_shares,
        encrypted_randomness,
        blob,
        aad,
        mac,
    }
}

// TODO: If fixed length vectors are ever supported, we should use that instead.
fun peel_tuple_u8(bcs: &mut sui::bcs::BCS, length: u64): vector<u8> {
    vector::tabulate!(length, |_| bcs.peel_u8())
}

public fun package_id(self: &EncryptedObject): &address {
    &self.package_id
}

public fun id(self: &EncryptedObject): &vector<u8> {
    &self.id
}

public fun services(self: &EncryptedObject): &vector<address> {
    &self.services
}

public fun indices(self: &EncryptedObject): &vector<u8> {
    &self.indices
}

public fun threshold(self: &EncryptedObject): u8 {
    self.threshold
}

public fun nonce(self: &EncryptedObject): &Element<G2> {
    &self.nonce
}

public fun encrypted_shares(self: &EncryptedObject): &vector<vector<u8>> {
    &self.encrypted_shares
}

public fun encrypted_randomness(self: &EncryptedObject): &vector<u8> {
    &self.encrypted_randomness
}

public fun blob(self: &EncryptedObject): &vector<u8> {
    &self.blob
}

public fun aad(self: &EncryptedObject): &Option<vector<u8>> {
    &self.aad
}

public fun mac(self: &EncryptedObject): &vector<u8> {
    &self.mac
}

#[test]
fun test_parse_encrypted_object() {
    let encoded =
        x"00000000000000000000000000000000000000000000000000000000000000000020381dd9078c322a4663c392761a0211b527c127b29583851217f948d62131f40903034401905bebdf8c04f3cd5f04f442a39372c8dc321c29edfb4f9cb30b23ab96b7d726ecf6f7036ee3557cd6c7b93a49b231070e8eecada9cfa157e40e3f02e5d3fcdba72804cc9504a82bbaa13ed4a83a0e2c6219d7e45125cf57fd10cbab957a977b02008812277be43199222d173eed91b480ce4c8cda5aea008ef884e77c990311136486a7daf8e2d99c0389ae40319714ffef1212ffcb456f0de08a7fa1bb185c936f9efe86fb5e32232d5e433230d04b1f2b27614b3b5b13f04db7d5c3b995e7e02e036315d5a9515d050595ea15b326ebcd510baf50463afd6517b5895d0756e39878bd656bd98418df11556d1ced740c7f839d97b81ee60238b3221fb45adfb0a5d1e4aec4f777271e5674bd7ded20421aa929755426501ba8366e465f5ebb861722b2909e5ac2e8608abd885014f2fb6006dd5896ab76ea243dea0d6d6ff4c3396b010de6062eb2dcb2f86bca32f83c9301200000000000000000000000000000000000000000000000000000000000000001184b788b4f5168aff51c0e6da7e2970caa02386c4dc179666ef4c6296807cda9";

    let object = parse_encrypted_object(encoded);
    assert!(object.package_id == @0x0);
    assert!(
        object.services == vector[@0x34401905bebdf8c04f3cd5f04f442a39372c8dc321c29edfb4f9cb30b23ab96, @0xd726ecf6f7036ee3557cd6c7b93a49b231070e8eecada9cfa157e40e3f02e5d3, @0xdba72804cc9504a82bbaa13ed4a83a0e2c6219d7e45125cf57fd10cbab957a97],
    );
    assert!(object.threshold == 2);
    assert!(
        object.nonce == g2_from_bytes(&x"8812277be43199222d173eed91b480ce4c8cda5aea008ef884e77c990311136486a7daf8e2d99c0389ae40319714ffef1212ffcb456f0de08a7fa1bb185c936f9efe86fb5e32232d5e433230d04b1f2b27614b3b5b13f04db7d5c3b995e7e02e"),
    );
    assert!(object.indices == x"b7fc7b");

    assert!(object.services.length() == 3);
    assert!(
        object.services[0] == @0x34401905bebdf8c04f3cd5f04f442a39372c8dc321c29edfb4f9cb30b23ab96,
    );
    assert!(
        object.services[1] == @0xd726ecf6f7036ee3557cd6c7b93a49b231070e8eecada9cfa157e40e3f02e5d3,
    );
    assert!(
        object.services[2] == @0xdba72804cc9504a82bbaa13ed4a83a0e2c6219d7e45125cf57fd10cbab957a97,
    );

    assert!(object.encrypted_shares.length() == 3);
    assert!(
        object.encrypted_shares[0] == x"6315d5a9515d050595ea15b326ebcd510baf50463afd6517b5895d0756e39878",
    );
    assert!(
        object.encrypted_shares[1] == x"bd656bd98418df11556d1ced740c7f839d97b81ee60238b3221fb45adfb0a5d1",
    );
    assert!(
        object.encrypted_shares[2] == x"e4aec4f777271e5674bd7ded20421aa929755426501ba8366e465f5ebb861722",
    );

    assert!(
        object.encrypted_randomness == x"b2909e5ac2e8608abd885014f2fb6006dd5896ab76ea243dea0d6d6ff4c3396b",
    );
    assert!(object.blob == x"e6062eb2dcb2f86bca32f83c93");

    assert!(
        object
            .aad
            .is_some_and!(
                |x| x == x"0000000000000000000000000000000000000000000000000000000000000001",
            ),
    );
    assert!(object.mac == x"184b788b4f5168aff51c0e6da7e2970caa02386c4dc179666ef4c6296807cda9");
}

#[test]
#[expected_failure]
fun test_parse_encrypted_object_duplicate_indices_rejected() {
    // a encoded object with duplicate indices [183, 183, 123]
    let encoded =
        x"00000000000000000000000000000000000000000000000000000000000000000020381dd9078c322a4663c392761a0211b527c127b29583851217f948d62131f40903034401905bebdf8c04f3cd5f04f442a39372c8dc321c29edfb4f9cb30b23ab96b7d726ecf6f7036ee3557cd6c7b93a49b231070e8eecada9cfa157e40e3f02e5d3b7dba72804cc9504a82bbaa13ed4a83a0e2c6219d7e45125cf57fd10cbab957a977b02008812277be43199222d173eed91b480ce4c8cda5aea008ef884e77c990311136486a7daf8e2d99c0389ae40319714ffef1212ffcb456f0de08a7fa1bb185c936f9efe86fb5e32232d5e433230d04b1f2b27614b3b5b13f04db7d5c3b995e7e02e036315d5a9515d050595ea15b326ebcd510baf50463afd6517b5895d0756e39878bd656bd98418df11556d1ced740c7f839d97b81ee60238b3221fb45adfb0a5d1e4aec4f777271e5674bd7ded20421aa929755426501ba8366e465f5ebb861722b2909e5ac2e8608abd885014f2fb6006dd5896ab76ea243dea0d6d6ff4c3396b010de6062eb2dcb2f86bca32f83c9301200000000000000000000000000000000000000000000000000000000000000001184b788b4f5168aff51c0e6da7e2970caa02386c4dc179666ef4c6296807cda9";

    let _ = parse_encrypted_object(encoded);
}

#[test]
fun test_verify_derived_key() {
    let public_key = sui::bls12381::g2_from_bytes(
        &x"ae7577bd3fe7f470f31ad2c9209e58eaa703d8585581d5e327e3c411805b7723b2f8403f7606d2c7bce6fafc27f3b091053c5e4b215e2e4be81877c499e7f26c5c7ebc0c5fdf657c53cd72f37cb1d9dc29e1a8f9cf5a8257a2f6ffdcb84589dc",
    );
    let derived_key = sui::bls12381::g1_from_bytes(
        &x"b86c7e836fe7c4b5ab9258f9e8c223b85db2892b3c91da2ad32e103ffad2238c38fd64e6fb9575c62a2076942cf28e9d",
    );
    let id = x"01020304";
    let full_id = create_full_id(@0x0, id);
    let gid = hash_to_g1_with_dst(&full_id);

    assert!(verify_derived_key(&derived_key, &gid, &public_key));

    let other_public_key = sui::bls12381::g2_from_bytes(
        &x"a0c2e4dd4830aec2d6c6bf13bb98e20db09a1354d48eabbe2cdbfeb36d3d8a87efb25c5f7ccc771f7b1c0e387bc6432b009dbd1ed9374059fb5b7c7497fddb2e8c5a08cd5cd1c0ae421868ca2c1250390223273288bcbb47ea4ac5e4850d6d27",
    );
    let other_derived_key = sui::bls12381::g1_from_bytes(
        &x"85e9ccf31b955739a70a18e20cfa77a44c0275c4781b563aaa453cfb7a947259df8f16be0ef4288d7994432f9f0f3713",
    );
    let other_full_id = create_full_id(@0x1, id);
    let other_gid = hash_to_g1_with_dst(&other_full_id);

    assert!(!verify_derived_key(&other_derived_key, &gid, &public_key));
    assert!(!verify_derived_key(&derived_key, &gid, &other_public_key));
    assert!(!verify_derived_key(&derived_key, &other_gid, &public_key));
}

#[test]
fun test_verify_derived_keys() {
    let public_key_1 = new_public_key(
        @0x0.to_id(),
        x"8fcce930177ddbe52e2efb4a81d306d67b4325bc9ac1abe9add4a357c1004e53e1956ecdae9395c527a838dea2b7ff5b1007c3793950bfb2f5cd053eab7925ce15189d42650aa88e93a7ad95aad45e8cdb99020fb9c83573673cd66a484bba80",
    );
    let public_key_2 = new_public_key(
        @0x0.to_id(),
        x"a5988b80eb9eda86299c1ffa7a9b8937dc6b576bf505f7ea3d5e5f5736ed176228289419d62c88aa3fd56cd1e11ee10d1348f4ab336f940763b1d5c6843a5233edbf51c294ad2afaf2dfede72998ec41c005d8a177df90bfb868449b6434791f",
    );
    let public_key_3 = new_public_key(
        @0x0.to_id(),
        x"b45f4e2988d9d2b2bda53d3c086bbd7b6a3d7ad8402f869bc58b55b0915e9dda5d2335b60054bcc177d049b879876f9d0c7f9d86d99eb33053bbbc36b1a48993d3f8590b50bec358323083f6edef4384e4581ff6e9c3757b92592bb990fdfddf",
    );

    let derived_key_1 = sui::bls12381::g1_from_bytes(
        &x"8b34f8188bedf3aa7cb87f94ce7bf457f5546dc47beb35b5a8a068d978caa7067558106d7868015a860b2404e943ecc3",
    );
    let derived_key_2 = sui::bls12381::g1_from_bytes(
        &x"834b2758d1d6ba335affc0b2268e3f9883e19984a501d6419e0d206d2819c9ea499eb8de8e24b9fb6bfd57d15769719c",
    );
    let derived_key_3 = sui::bls12381::g1_from_bytes(
        &x"9274d5ca9113924e81fad704c36147758f1178212a15c29e072d55cf8d405e07b8730f3794bc6519d17e9cf0d519f38d",
    );

    let id = x"01020304";
    let package_id = @0x0;

    let verfied_derived_keys = verify_derived_keys(
        &vector[derived_key_1, derived_key_2, derived_key_3],
        package_id,
        id,
        &vector[public_key_1, public_key_2, public_key_3],
    );

    assert!(verfied_derived_keys.length() == 3);
}

#[test]
#[expected_failure]
fun test_verify_invalid_derived_keys() {
    let public_key_1 = new_public_key(
        @0x0.to_id(),
        x"8fcce930177ddbe52e2efb4a81d306d67b4325bc9ac1abe9add4a357c1004e53e1956ecdae9395c527a838dea2b7ff5b1007c3793950bfb2f5cd053eab7925ce15189d42650aa88e93a7ad95aad45e8cdb99020fb9c83573673cd66a484bba80",
    );
    let public_key_2 = new_public_key(
        @0x0.to_id(),
        x"a5988b80eb9eda86299c1ffa7a9b8937dc6b576bf505f7ea3d5e5f5736ed176228289419d62c88aa3fd56cd1e11ee10d1348f4ab336f940763b1d5c6843a5233edbf51c294ad2afaf2dfede72998ec41c005d8a177df90bfb868449b6434791f",
    );
    let public_key_3 = new_public_key(
        @0x0.to_id(),
        x"b45f4e2988d9d2b2bda53d3c086bbd7b6a3d7ad8402f869bc58b55b0915e9dda5d2335b60054bcc177d049b879876f9d0c7f9d86d99eb33053bbbc36b1a48993d3f8590b50bec358323083f6edef4384e4581ff6e9c3757b92592bb990fdfddf",
    );

    let invalid_derived_key_1 = sui::bls12381::g1_from_bytes(
        &x"b422f84796342a08487df375e705d896e2eef13aded6e2c64344eb6c0c795020741173489994f238891491e8026a5992",
    );
    let derived_key_2 = sui::bls12381::g1_from_bytes(
        &x"834b2758d1d6ba335affc0b2268e3f9883e19984a501d6419e0d206d2819c9ea499eb8de8e24b9fb6bfd57d15769719c",
    );
    let derived_key_3 = sui::bls12381::g1_from_bytes(
        &x"9274d5ca9113924e81fad704c36147758f1178212a15c29e072d55cf8d405e07b8730f3794bc6519d17e9cf0d519f38d",
    );

    let id = x"01020304";
    let package_id = @0x0;

    verify_derived_keys(
        &vector[invalid_derived_key_1, derived_key_2, derived_key_3],
        package_id,
        id,
        &vector[public_key_1, public_key_2, public_key_3],
    );
}

#[test]
fun test_inconsistent_shares() {
    use sui::bls12381::g1_from_bytes;

    // Test vector generated using the Rust unit test: https://github.com/MystenLabs/seal/blob/bd523e897c7b1ca2c89f239069a85752dcd43a93/crates/crypto/src/lib.rs#L667-L725
    let encrypted_object = parse_encrypted_object(
        x"0001c83873c4a8e5934501f26cf5e82057ea8316ba9be6b35df42ae83b87746bae040102030403e9819a166e94f227405f77ae24c5a078cce38f37a90f20521607e6eb6135f8a301ffd18f0cec409c1c87e4765f0073f0dae5e1294e97ec102f7f73f1aecc7375ed02795b7179463ffc21f7182862cbfb7e9dd56ba9b1770e1144dfebcabe2d970dfb030200aeb3147dcf252de39d64d4784d2c1442845a4d85c58e9fd8d0a97de7ce6c1b7a335b6da71e9d5d2a88a60dab480e76dd0e234545ceeb81c36078ac2acf2928f6169212a5b52d83cb60964ea48a9267d5b0ecd15563f90f0250e4df397b3a920803062af76d555e6587ef7e31990ab0b0cd475fc440aa4ca4dc4e1a7d6292f816877c1e2105eaeeb7efa6891484afdddd44773a8cfc44d27cb7cf7f976571985f215bbdad9f398e8135d6362fef863c2f264a701e5f5aeaf55ea660c1f34d56a2ee6b953c332a0d7655133a49d7d8fdfd6a26c47348a845e1c98121034018bddb3a010d0a7e4ce9c3531c57f41b925c670109736f6d657468696e67717fd46482a5ed5094279a6b59b57105989efd0fe895ee12b986acf94d03d6e0",
    );

    let pk0_bytes =
        x"a92411a2e7ff0a76bfb4e6e033b114e15908884778defef5d13b31bd9a6c7d0440aa6ffca5bc1a3e0448594b032fe9310e4c33b8f8134f495698c00965385bc6c680bd0fa5224309ee7f537096b44e0baf4a23a382873156a747178fc9f1365c";
    let pk1_bytes =
        x"870b95522bf7e89b43cbda10c37ece8a71226e3d07f2bed7e353e88abd9467dce75fcdb165886832ad3d6e5502c43465112748fce3f44ff824365bf398f5f9cc9544149c74736cd2c7caf54137489b57c9345d47473768f85197c2ff3928879a";
    let pk2_bytes =
        x"ae4d78e2851c0945ee45d8452cbd7026871cf042ee396f09d1f64841db5026a0edc1d5da6f030cfde62112d5d6bf6f9606ed3d4913494741cab577c7e860437f564df0ba7868262e525614cd4e9c8f4d1c50e36542c00ae86178b83d061cf601";

    let public_keys = vector[
        new_public_key(encrypted_object.services[0].to_id(), pk0_bytes),
        new_public_key(encrypted_object.services[1].to_id(), pk1_bytes),
        new_public_key(encrypted_object.services[2].to_id(), pk2_bytes),
    ];
    let some_public_keys = vector[
        // new_public_key(encrypted_object.services[0], pk0_bytes),
        new_public_key(encrypted_object.services[1].to_id(), pk1_bytes),
        new_public_key(encrypted_object.services[2].to_id(), pk2_bytes),
    ];

    // let usk0 = g1_from_bytes(&x"b17efcfcd5da311d857c6f2becfe6333eae5b17217dc37532de283ecdefb7c297b2177a3ee7c41008dd87e188325acd1");
    let usk1 = g1_from_bytes(
        &x"b22dadcaa4787729141c936a773f78ff2eed8a3f0507eb65298dc4aa3362076891c54430fe24821d081c80d35f096eb3",
    );
    let usk2 = g1_from_bytes(
        &x"986980b01b2b410c0d174253d36010626d30edac624cf8702f2079bb59245b17fbea26d5e1cdf3fc4dd088b82233c3e6",
    );

    let vdks = verify_derived_keys(
        &vector[usk1, usk2],
        encrypted_object.package_id,
        encrypted_object.id,
        &some_public_keys,
    );

    let decrypted = decrypt(&encrypted_object, &vdks, &public_keys);
    assert!(decrypted.is_none());
}

#[test]
fun test_decryption() {
    use sui::bls12381::{g1_from_bytes};

    let pk0 =
        x"a58bfa576a8efe2e2730bc664b3dbe70257d8e35106e4af7353d007dba092d722314a0aeb6bca5eed735466bbf471aef01e4da8d2efac13112c51d1411f6992b8604656ea2cf6a33ec10ce8468de20e1d7ecbfed8688a281d462f72a41602161";
    let pk1 =
        x"a9ce55cfa7009c3116ea29341151f3c40809b816f4ad29baa4f95c1bb23085ef02a46cf1ae5bd570d99b0c6e9faf525306224609300b09e422ae2722a17d2a969777d53db7b52092e4d12014da84bffb1e845c2510e26b3c259ede9e42603cd6";
    let pk2 =
        x"93b3220f4f3a46fb33074b590cda666c0ebc75c7157d2e6492c62b4aebc452c29f581361a836d1abcbe1386268a5685103d12dec04aadccaebfa46d4c92e2f2c0381b52d6f2474490d02280a9e9d8c889a3fce2753055e06033f39af86676651";

    // For reference, the encryption was created with the following CLI command:
    // cargo run --bin seal-cli encrypt-hmac --message 48656C6C6F2C20776F726C6421 --aad 0x0000000000000000000000000000000000000000000000000000000000000001 --package-id 0x0 --id 381dd9078c322a4663c392761a0211b527c127b29583851217f948d62131f409 --threshold 2 a58bfa576a8efe2e2730bc664b3dbe70257d8e35106e4af7353d007dba092d722314a0aeb6bca5eed735466bbf471aef01e4da8d2efac13112c51d1411f6992b8604656ea2cf6a33ec10ce8468de20e1d7ecbfed8688a281d462f72a41602161 a9ce55cfa7009c3116ea29341151f3c40809b816f4ad29baa4f95c1bb23085ef02a46cf1ae5bd570d99b0c6e9faf525306224609300b09e422ae2722a17d2a969777d53db7b52092e4d12014da84bffb1e845c2510e26b3c259ede9e42603cd6 93b3220f4f3a46fb33074b590cda666c0ebc75c7157d2e6492c62b4aebc452c29f581361a836d1abcbe1386268a5685103d12dec04aadccaebfa46d4c92e2f2c0381b52d6f2474490d02280a9e9d8c889a3fce2753055e06033f39af86676651 -- 0x34401905bebdf8c04f3cd5f04f442a39372c8dc321c29edfb4f9cb30b23ab96 0xd726ecf6f7036ee3557cd6c7b93a49b231070e8eecada9cfa157e40e3f02e5d3 0xdba72804cc9504a82bbaa13ed4a83a0e2c6219d7e45125cf57fd10cbab957a97
    let encrypted_object =
        x"00000000000000000000000000000000000000000000000000000000000000000020381dd9078c322a4663c392761a0211b527c127b29583851217f948d62131f40903034401905bebdf8c04f3cd5f04f442a39372c8dc321c29edfb4f9cb30b23ab9601d726ecf6f7036ee3557cd6c7b93a49b231070e8eecada9cfa157e40e3f02e5d302dba72804cc9504a82bbaa13ed4a83a0e2c6219d7e45125cf57fd10cbab957a97030200b687baf3e9b78786fa50237861cb07f5f25febd790769eec41859f353deed5ab6301cbbf4e2616effe8a04a0b46dd2101531117eed7514e59f9ddbf33119eaeb2fd85c35e9c01cccc5a1d20c7000afbc4ad95ff11de52e098ee129be51d6b63b034693204591c2f2904595850da29007772266e36faecf2385c19daca728d8cd4fa354f4cb57faee6f19bff2d7f2736646bb07048a9355869a6975f0c338030d6d422ddfc436e3d077be2c53b521dd73416e9c57ccf53003456d9bc18c1e9b6020825d9248023240d255fe4897349d2e0a0f5a1c32c68a48c45eba309fd5fa8510010d59416fff28cf98412a42787bbc012000000000000000000000000000000000000000000000000000000000000000017b70af332dbf79873c7fa4996aceec9e9507210e34f0bc3066e7328beedeabc8";

    let parsed_encrypted_object = parse_encrypted_object(encrypted_object);

    let pks = vector[
        new_public_key(parsed_encrypted_object.services[0].to_id(), pk0),
        new_public_key(parsed_encrypted_object.services[1].to_id(), pk1),
        //new_public_key(parsed_encrypted_object.services[2].to_id(), pk2),
    ];

    // cargo run --bin seal-cli extract --package-id 0x0 --id 381dd9078c322a4663c392761a0211b527c127b29583851217f948d62131f409 --master-key 3c185eb32f1ab43a013c7d84659ec7b59791ca76764af4ee8d387bf05621f0c7
    let usk0 =
        x"8cb19351dbd351d02292a77a18e2f0f4ec0d3becf23f37cc87e4870bf35522c3e59487e0ee5023d5e2e383e40b77bd98";
    // cargo run --bin seal-cli extract --package-id 0x0 --id 381dd9078c322a4663c392761a0211b527c127b29583851217f948d62131f409 --master-key 09ba20939b2300c5ffa42e71809d3dc405b1e68259704b3cb8e04c36b0033e24
    let usk1 =
        x"a7f6b22719b8ca2e3bfc07bf22ea59245b4aec7a394020cf826199b3cc71e58045e5d6b52506145851e71370e524c362";

    let user_secret_keys = vector[g1_from_bytes(&usk0), g1_from_bytes(&usk1)];
    let vdks = verify_derived_keys(
        &user_secret_keys,
        @0x0,
        x"381dd9078c322a4663c392761a0211b527c127b29583851217f948d62131f409",
        &pks,
    );

    let all_pks = vector[
        new_public_key(parsed_encrypted_object.services[0].to_id(), pk0),
        new_public_key(parsed_encrypted_object.services[1].to_id(), pk1),
        new_public_key(parsed_encrypted_object.services[2].to_id(), pk2),
    ];

    let decrypted = decrypt(&parsed_encrypted_object, &vdks, &all_pks);
    assert!(decrypted.borrow() == b"Hello, world!");
}

#[test]
fun test_decryption_one_server() {
    use sui::bls12381::{g1_from_bytes};

    let pk0 =
        x"a58bfa576a8efe2e2730bc664b3dbe70257d8e35106e4af7353d007dba092d722314a0aeb6bca5eed735466bbf471aef01e4da8d2efac13112c51d1411f6992b8604656ea2cf6a33ec10ce8468de20e1d7ecbfed8688a281d462f72a41602161";

    // For reference, the encryption was created with the following CLI command:
    // cargo run --bin seal-cli encrypt-hmac --message 48656C6C6F2C20776F726C6421 --aad 0x0000000000000000000000000000000000000000000000000000000000000001 --package-id 0x0 --id 381dd9078c322a4663c392761a0211b527c127b29583851217f948d62131f409 --threshold 1 a58bfa576a8efe2e2730bc664b3dbe70257d8e35106e4af7353d007dba092d722314a0aeb6bca5eed735466bbf471aef01e4da8d2efac13112c51d1411f6992b8604656ea2cf6a33ec10ce8468de20e1d7ecbfed8688a281d462f72a41602161 -- 0x34401905bebdf8c04f3cd5f04f442a39372c8dc321c29edfb4f9cb30b23ab96
    let encrypted_object =
        x"00000000000000000000000000000000000000000000000000000000000000000020381dd9078c322a4663c392761a0211b527c127b29583851217f948d62131f40901034401905bebdf8c04f3cd5f04f442a39372c8dc321c29edfb4f9cb30b23ab96010100b7452a3ea753ef5ba8afa990cac0b48319a583a13443bfd34ad172601434669963b530cd587d54d6eaa58685c3b0516b02050261e5c8a18f21cb9dd41803ab66baaff02c987e33ea9bd579d541dcc5d5608fe08751888d4360c4405d6aea0b65017f724abd69e0825e4aa59cdd8cb271333bc4e35587f6e7775a1dfb1f15f3d8018e3b2279ee7c5ae1b51152ff2b85177dda0ef60cdf065c72ed98b108575aa6fa010d798e404fbf5cb28034b941a6d4012000000000000000000000000000000000000000000000000000000000000000018a00ea13a81aa512647815af7d535b3c9248b142c0f825a6a15acdc778229453";

    let parsed_encrypted_object = parse_encrypted_object(encrypted_object);

    let pks = vector[new_public_key(parsed_encrypted_object.services[0].to_id(), pk0)];

    // cargo run --bin seal-cli extract --package-id 0x0 --id 381dd9078c322a4663c392761a0211b527c127b29583851217f948d62131f409 --master-key 3c185eb32f1ab43a013c7d84659ec7b59791ca76764af4ee8d387bf05621f0c7
    let usk0 =
        x"8cb19351dbd351d02292a77a18e2f0f4ec0d3becf23f37cc87e4870bf35522c3e59487e0ee5023d5e2e383e40b77bd98";

    let user_secret_keys = vector[g1_from_bytes(&usk0)];
    let vdks = verify_derived_keys(
        &user_secret_keys,
        @0x0,
        x"381dd9078c322a4663c392761a0211b527c127b29583851217f948d62131f409",
        &pks,
    );

    let all_pks = vector[new_public_key(parsed_encrypted_object.services[0].to_id(), pk0)];

    let decrypted = decrypt(&parsed_encrypted_object, &vdks, &all_pks);
    assert!(decrypted.borrow() == b"Hello, world!");
}

#[test]
#[expected_failure]
fun test_decryption_too_few_shares() {
    use sui::bls12381::{g1_from_bytes};

    let pk0 =
        x"a58bfa576a8efe2e2730bc664b3dbe70257d8e35106e4af7353d007dba092d722314a0aeb6bca5eed735466bbf471aef01e4da8d2efac13112c51d1411f6992b8604656ea2cf6a33ec10ce8468de20e1d7ecbfed8688a281d462f72a41602161";
    let pk1 =
        x"a9ce55cfa7009c3116ea29341151f3c40809b816f4ad29baa4f95c1bb23085ef02a46cf1ae5bd570d99b0c6e9faf525306224609300b09e422ae2722a17d2a969777d53db7b52092e4d12014da84bffb1e845c2510e26b3c259ede9e42603cd6";
    let pk2 =
        x"93b3220f4f3a46fb33074b590cda666c0ebc75c7157d2e6492c62b4aebc452c29f581361a836d1abcbe1386268a5685103d12dec04aadccaebfa46d4c92e2f2c0381b52d6f2474490d02280a9e9d8c889a3fce2753055e06033f39af86676651";

    let encrypted_object =
        x"00000000000000000000000000000000000000000000000000000000000000000020381dd9078c322a4663c392761a0211b527c127b29583851217f948d62131f40903034401905bebdf8c04f3cd5f04f442a39372c8dc321c29edfb4f9cb30b23ab9601d726ecf6f7036ee3557cd6c7b93a49b231070e8eecada9cfa157e40e3f02e5d302dba72804cc9504a82bbaa13ed4a83a0e2c6219d7e45125cf57fd10cbab957a97030200b687baf3e9b78786fa50237861cb07f5f25febd790769eec41859f353deed5ab6301cbbf4e2616effe8a04a0b46dd2101531117eed7514e59f9ddbf33119eaeb2fd85c35e9c01cccc5a1d20c7000afbc4ad95ff11de52e098ee129be51d6b63b034693204591c2f2904595850da29007772266e36faecf2385c19daca728d8cd4fa354f4cb57faee6f19bff2d7f2736646bb07048a9355869a6975f0c338030d6d422ddfc436e3d077be2c53b521dd73416e9c57ccf53003456d9bc18c1e9b6020825d9248023240d255fe4897349d2e0a0f5a1c32c68a48c45eba309fd5fa8510010d59416fff28cf98412a42787bbc012000000000000000000000000000000000000000000000000000000000000000017b70af332dbf79873c7fa4996aceec9e9507210e34f0bc3066e7328beedeabc8";

    let parsed_encrypted_object = parse_encrypted_object(encrypted_object);

    let pks = vector[new_public_key(parsed_encrypted_object.services[0].to_id(), pk0)];

    let usk0 =
        x"8cb19351dbd351d02292a77a18e2f0f4ec0d3becf23f37cc87e4870bf35522c3e59487e0ee5023d5e2e383e40b77bd98";

    let user_secret_keys = vector[g1_from_bytes(&usk0)];
    let vdks = verify_derived_keys(
        &user_secret_keys,
        @0x0,
        x"381dd9078c322a4663c392761a0211b527c127b29583851217f948d62131f409",
        &pks,
    );

    let all_pks = vector[
        new_public_key(parsed_encrypted_object.services[0].to_id(), pk0),
        new_public_key(parsed_encrypted_object.services[1].to_id(), pk1),
        new_public_key(parsed_encrypted_object.services[2].to_id(), pk2),
    ];

    decrypt(&parsed_encrypted_object, &vdks, &all_pks);
}

#[test]
fun test_decryption_invalid_usk() {
    use sui::bls12381::g1_from_bytes;

    let pk0 =
        x"8c7c2ded63f7ab30fe578f850349098c9537d4f7bc32ca45bbb45ac7254e696bf8c58ba71ea3d631abd03223b297cb8608e99455e276fdaf0ad24ece7b7fe835ec73b051d8622295627ed98c50e77c54d0529410c1d7025f57d90374fab18c52";
    let pk1 =
        x"8483124f1ac60c5996f36fb217767b0262da1e321ea755242e10c4682466f1ef5f2d2a345d2bb904ae6218542ac92027134afd8794d52901838e9ca5a15f43258b146672495442b8fb5c98ef3b7147ed2739769096e16bd51009e81d51ad77b6";
    let pk2 =
        x"93bb6464314f978c59324cb818b18131e500f7d60bcba09e3aa00e227e688e7f0b8588d37b10a83fbcde255f479c23c605a7e8f120e23dc1098f8267a901fe9537bef3dba5e24bc59b84a5227f4501daa0b70f056f6efe0359a5f6b7e0a2cb11";
    let encrypted_object =
        x"0000000000000000000000000000000000000000000000000000000000000000000401020304030000000000000000000000000000000000000000000000000000000000000001010000000000000000000000000000000000000000000000000000000000000002020000000000000000000000000000000000000000000000000000000000000003030200b033d20cbcd66b8bf60345065f376e1b15387d5628106be2d27ec2736f7eb8570d2e98eb6b4adbbc3e0290a53b9ede93147895a3a3e693d6531c05d28cc002da7f0a3b529a53f41eec23f3a92f5cfa757e5d680a10b866e33644da02e39c6fbe0379efc1173902a140e49cebb7382ce2237a6d99583e8bb7984afd1a5f077b436a0f97672ecee3138690b4901ca3a1813c4bf743b8d0ce20f11cc67004fe6913fbceda166a681cacb1e9f8c7f5d3d096ec4c7e8ec691f30712cc8f7641ca08399d442aae27ae0c4e6a7e56cb077ec5a30b4d5c1350cc3934219a0371d95d17257e010d82ce7de56a5b2378b0f68ea8470109736f6d657468696e67d47a95162d980ddcef6e15255204130cc2fb5a2cdaa418a92e3f85e1538c73e8";
    let parsed_encrypted_object = parse_encrypted_object(encrypted_object);

    let pks = vector[
        new_public_key(parsed_encrypted_object.services[0].to_id(), pk0),
        new_public_key(parsed_encrypted_object.services[1].to_id(), pk1),
    ];

    let usk0 =
        x"852e8f37b45b153cc5121848c6ef2f3539b2de8d3f5b5b80e57ea115f65883b7d17b68637356159cfcdd546f1bd671cc";
    let usk1 =
        x"ada471bc5a75eb99dc3bbe9ed2bc7a598529b7b86de6d8a569fc0b6381117b58097bb49e64f8105a87654e7e58f30b0d";

    let user_secret_keys = vector[g1_from_bytes(&usk0), g1_from_bytes(&usk1)];
    let vdks = verify_derived_keys(
        &user_secret_keys,
        parsed_encrypted_object.package_id,
        parsed_encrypted_object.id,
        &pks,
    );

    let all_pks = vector[
        new_public_key(parsed_encrypted_object.services[0].to_id(), pk0),
        new_public_key(parsed_encrypted_object.services[1].to_id(), pk1),
        new_public_key(parsed_encrypted_object.services[2].to_id(), pk2),
    ];

    let decrypted = decrypt(&parsed_encrypted_object, &vdks, &all_pks);
    assert!(decrypted.borrow() == b"Hello, World!");

    // Use a usk derived from a different key pair but for the same object id
    let other_pk0 =
        x"8f7a86ee2fac3c635b4394deab61ced2a05c01b0669d43364ceb3ae2ba8648e2a02b5bdb0fa34cd146afc776dfc374890da84f1e973263571a7b1a67f80d80a1b5fc2d2caf9abd8c3b663bfb4fa78814dc54d7c182769d492ff89a6b6102f55b";
    let other_usk0 =
        x"ae81562ca1748f625b818b92829e07eb67d9ce646005ea893f8d364c5ee01174faf7e85e0de8307021c67aadb30190ed";
    let pks = vector[
        new_public_key(parsed_encrypted_object.services[0].to_id(), other_pk0),
        new_public_key(parsed_encrypted_object.services[1].to_id(), pk1),
        //new_public_key(parsed_encrypted_object.services[2].to_id(), pk2),
    ];
    let all_pks = vector[
        new_public_key(parsed_encrypted_object.services[0].to_id(), other_pk0),
        new_public_key(parsed_encrypted_object.services[1].to_id(), pk1),
        new_public_key(parsed_encrypted_object.services[2].to_id(), pk2),
    ];
    let user_secret_keys = vector[g1_from_bytes(&other_usk0), g1_from_bytes(&usk1)];
    let vdks = verify_derived_keys(
        &user_secret_keys,
        parsed_encrypted_object.package_id,
        parsed_encrypted_object.id,
        &pks,
    );

    // Fails during decryption. In this case it fails since decryption of the randomness fails.
    assert!(decrypt(&parsed_encrypted_object, &vdks, &all_pks).is_none());
}

#[test]
#[expected_failure]
fun test_zero_threshold() {
    parse_encrypted_object(
        x"00571ce2217b77605970898d1ddb29e235ed46d0768c6d32e28509ed0678f678080401020304000000c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010d48656c6c6f2c20576f726c64210109736f6d657468696e670000000000000000000000000000000000000000000000000000000000000000",
    );
}

#[test]
fun test_decryption_from_sdk() {
    use sui::bls12381::{g1_from_bytes};

    // Test vector from SDK -- print PKs, encryption and derived keys from 'test getDerivedKeys'

    let pk0 =
        x"a8efa40cb7f94048904b26526a6d7cb1363d5b6e5d317d06eefda3a62c685c20c20018dff944c9ed67293bec5dfafeb211aa615a8f4bcb0d1e7257bc9701ec2da9d45ae6b0ed2bf3aae350f841bf550cf145c782d132d4dcf76afb35515a652b";
    let pk1 =
        x"af022ea8355995b863a43b6634954a3af5ec9cc14084fabcfce79367c35d0b03d4fd15e912704e64175f3d2a58829ab013379982bda344f2b65fc04813ea9f0ae920a6ae165d0fc9cb3f7d20cde5a3883ee660a0c5e8221ff5a3aae6babe669a";

    let encrypted_object =
        x"008afa5d31dbaa0a8fb07082692940ca3d56b5e856c5126cb5a3693f0a4de63b82205809c296d41e0d6177e8cf956010c1d2387299892bb9122ca4ba4ffd165e05cb023cf2a38f061ede3239c1629cb80a9be0e0676b1c15d34c94d104d4ba9d99076f0181aeaa8c25d2c912e1dc23b4372305b7a602c4ec4cc3e510963bc635e500aa37020200a4a3c3f42e4b30cb2926ef3247cfeb056027e8518c277bae03abc754bf34817fc803257a6fd5503ddc1f58f93c735cd219b0e2384014e84feddac5e0cf579be19b1afa42c5ffd8ca6b70070a569b98de59f03dff1d2ae11d24de92bc498ae666027010da668f4afd9491668ab40aba618eee3365a5f97c6c4795043b35e298d7a826e223ac636377538c303e756f8efd2c4b1858f21c9cb9b045d5b061deb348bc84dfcb593d51e59f298a4e2faca80b94d5dd3822b584abf759d8b8bc78a8380e0103dff0f201007d56f2bf4cb3ec66527892198502c6b76282fdbd57e1af2ccf3fc56b15c9ea8e";

    let parsed_encrypted_object = parse_encrypted_object(encrypted_object);

    let pks = vector[
        new_public_key(parsed_encrypted_object.services[0].to_id(), pk0),
        new_public_key(parsed_encrypted_object.services[1].to_id(), pk1),
    ];

    let usk0 =
        x"abe09fb34c00508aec5ba32657388453b09df06ffda7e2e84ba79016ef9ac60c865d0c5e231bd2be187d42f88ad17fd6";
    let usk1 =
        x"80962df1763bc11aa373fe572c52bb04840a604bbf3fa57c0d75fe987c55ac1b42934b36cf775e02cf1f639e3a4e77e9";

    let user_secret_keys = vector[g1_from_bytes(&usk0), g1_from_bytes(&usk1)];
    let vdks = verify_derived_keys(
        &user_secret_keys,
        @0x8afa5d31dbaa0a8fb07082692940ca3d56b5e856c5126cb5a3693f0a4de63b82,
        x"5809c296d41e0d6177e8cf956010c1d2387299892bb9122ca4ba4ffd165e05cb",
        &pks,
    );

    let decrypted = decrypt(&parsed_encrypted_object, &vdks, &pks);
    assert!(decrypted.borrow() == x"010203");
}

#[test]
#[expected_failure]
fun test_all_unique_failure() {
    assert_all_unique(&vector[1, 2, 3, 1]);
}

#[test]
fun test_all_unique_success() {
    assert_all_unique(&vector[4, 1, 2, 3]);
    assert_all_unique(&vector[1]);
    assert_all_unique(&vector<u8>[]);
}

#[test]
fun test_safe_scalar_from_bytes() {
    // p - 1
    let valid_bytes = x"73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000000";
    assert!(safe_scalar_from_bytes(&valid_bytes).is_some());

    // p
    let invalid_bytes = x"73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001";
    assert!(safe_scalar_from_bytes(&invalid_bytes).is_none());

    // 0
    let zero = x"0000000000000000000000000000000000000000000000000000000000000000";
    assert!(safe_scalar_from_bytes(&zero).is_some_and!(|v| v == sui::bls12381::scalar_from_u64(0)));

    // 7
    let seven = x"0000000000000000000000000000000000000000000000000000000000000007";
    assert!(
        safe_scalar_from_bytes(&seven).is_some_and!(|v| v == sui::bls12381::scalar_from_u64(7)),
    );

    // 2^256 - 1
    let invalid_bytes = x"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    assert!(safe_scalar_from_bytes(&invalid_bytes).is_none());

    // Short input
    let short_bytes = x"73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF000000";
    assert!(safe_scalar_from_bytes(&short_bytes).is_none());

    // Short input
    let long_bytes = x"73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF0000000000";
    assert!(safe_scalar_from_bytes(&long_bytes).is_none());
}
