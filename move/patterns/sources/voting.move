// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Voting pattern:
/// - Anyone can create a vote with a set of voters.
/// - The voters can submit their encrypted votes.
/// - After all the voters have submitted votes, anyone can retrieve the encryption keys and submit them. The votes are then decrypted on-chain.
///
/// This is an example of on-chain decryption. Other use cases of this include auctions, timelocked voting, etc.
///
/// This pattern does NOT implement versioning, please see other patterns for
/// examples of versioning.
///
module patterns::voting;

use seal::bf_hmac_encryption::{
    EncryptedObject,
    VerifiedDerivedKey,
    PublicKey,
    decrypt,
    new_public_key,
    verify_derived_keys,
    parse_encrypted_object
};
use sui::bls12381::g1_from_bytes;

const EInvalidVote: u64 = 1;
const EVoteNotDone: u64 = 2;
const EAlreadyFinalized: u64 = 3;
const ENotEnoughKeys: u64 = 4;

/// This represents a vote.
public struct Vote has key {
    /// The id of a vote is the id of the object.
    id: UID,
    /// The eligble voters of the vote.
    voters: vector<address>,
    /// This holds the encrypted votes assuming the same order as the `voters` vector.
    votes: vector<Option<EncryptedObject>>,
    /// This will be set after the vote is finalised. The vote options are represented by a Option<u8> which is None if the vote was invalid.
    result: Option<vector<Option<u8>>>,
    /// The key servers that must be used for the encryption of the votes.
    key_servers: vector<address>,
    /// The public keys for the key servers in the same order as `key_servers`.
    public_keys: vector<vector<u8>>,
    /// The threshold for the vote.
    threshold: u8,
}

// The id of a vote is the id of the object.
public fun id(v: &Vote): vector<u8> {
    object::id(v).to_bytes()
}

#[test_only]
public fun destroy_for_testing(v: Vote) {
    let Vote { id, .. } = v;
    object::delete(id);
}

/// Create a vote.
/// The associated key-ids are [pkg id][vote id].
public fun create_vote(
    voters: vector<address>,
    key_servers: vector<address>,
    public_keys: vector<vector<u8>>,
    threshold: u8,
    ctx: &mut TxContext,
): Vote {
    assert!(threshold <= key_servers.length() as u8);
    assert!(key_servers.length() == public_keys.length());
    Vote {
        id: object::new(ctx),
        voters,
        key_servers,
        public_keys,
        threshold,
        votes: vector::tabulate!(voters.length(), |_| option::none()),
        result: option::none(),
    }
}

/// Cast a vote.
/// The encrypted object should be an encryption of a single u8 and have the senders address as aad.
public fun cast_vote(vote: &mut Vote, encrypted_vote: vector<u8>, ctx: &mut TxContext) {
    let encrypted_vote = parse_encrypted_object(encrypted_vote);

    // The voter id must be put as aad to ensure that an encrypted vote cannot be copied and cast by another voter.
    assert!(encrypted_vote.aad().borrow() == ctx.sender().to_bytes(), EInvalidVote);

    // All encrypted vote must have been encrypted using the same key servers and the same threshold.
    // We could allow the order of the key servers to be different, but for the sake of simplicity, we also require the same order.
    assert!(encrypted_vote.services() == vote.key_servers, EInvalidVote);
    assert!(encrypted_vote.threshold() == vote.threshold, EInvalidVote);

    // Check that the encryptions were created for this vote.
    assert!(encrypted_vote.id() == vote.id(), EInvalidVote);
    assert!(encrypted_vote.package_id() == @0x0, EInvalidVote);

    // This aborts if the sender is not a voter.
    let index = vote.voters.find_index!(|voter| voter == ctx.sender()).destroy_some();
    vote.votes[index].fill(encrypted_vote);
}

entry fun seal_approve(id: vector<u8>, vote: &Vote) {
    assert!(id == vote.id(), EInvalidVote);
    assert!(vote.votes.all!(|vote| vote.is_some()), EVoteNotDone);
}

/// Finalize a vote.
/// Updates the `result` field of the vote to hold the votes of the corresponding voters.
/// Aborts if the vote has already been finalized.
/// Aborts if there are not enough keys or if they are not valid, e.g. if they were derived for a different purpose.
/// In case the keys are valid but a vote, is invalid, decrypt will just set the corresponding result to none.
///
/// The given derived keys and key servers should be in the same order.
public fun finalize_vote(
    vote: &mut Vote,
    derived_keys: &vector<vector<u8>>,
    key_servers: &vector<address>,
) {
    assert!(key_servers.length() == derived_keys.length());
    assert!(vote.result.is_none(), EAlreadyFinalized);
    assert!(derived_keys.length() as u8 >= vote.threshold, ENotEnoughKeys);

    // Public keys for the given derived keys
    let public_keys = key_servers
        .map_ref!(|ks1| vote.key_servers.find_index!(|ks2| ks1 == ks2).destroy_some())
        .map!(|i| new_public_key(vote.key_servers[i].to_id(), vote.public_keys[i]));

    // Verify the derived keys
    let verified_derived_keys: vector<VerifiedDerivedKey> = verify_derived_keys(
        &derived_keys.map_ref!(|k| g1_from_bytes(k)),
        @0x0,
        vote.id(),
        &public_keys,
    );

    // Public keys for all key servers
    let all_public_keys: vector<PublicKey> = vote
        .key_servers
        .zip_map!(vote.public_keys, |ks, pk| new_public_key(ks.to_id(), pk));

    // This aborts if there are not enough keys or if they are invalid, e.g. if they were derived for a different purpose.
    // However, in case the keys are valid but some of the encrypted objects, aka the votes, are invalid, decrypt will just return none for these votes.
    vote.result.fill(vote.votes.map_ref!(|vote| {
        let decrypted = decrypt(vote.borrow(), &verified_derived_keys, &all_public_keys);
        if (decrypted.is_some()) {
            let v = decrypted.borrow();
            // We expect the vote to be a single byte.
            if (v.length() == 1) {
                return option::some(v[0])
            }
        };
        option::none()
    }));
    // The encrypted votes can be deleted here if they are not needed anymore.
}

#[test]
fun test_vote() {
    use seal::key_server::{create_and_transfer_v1, KeyServer, destroy_for_testing as ks_destroy};
    use sui::test_scenario::{Self, next_tx, ctx};

    let addr1 = @0xA;
    let mut scenario = test_scenario::begin(addr1);

    // Setup key servers.
    let pk0 =
        x"a58bfa576a8efe2e2730bc664b3dbe70257d8e35106e4af7353d007dba092d722314a0aeb6bca5eed735466bbf471aef01e4da8d2efac13112c51d1411f6992b8604656ea2cf6a33ec10ce8468de20e1d7ecbfed8688a281d462f72a41602161";
    create_and_transfer_v1(
        b"mysten0".to_string(),
        b"https://mysten-labs.com".to_string(),
        0,
        pk0,
        scenario.ctx(),
    );
    scenario.next_tx(addr1);
    let s0: KeyServer = scenario.take_from_sender();

    let pk1 =
        x"a9ce55cfa7009c3116ea29341151f3c40809b816f4ad29baa4f95c1bb23085ef02a46cf1ae5bd570d99b0c6e9faf525306224609300b09e422ae2722a17d2a969777d53db7b52092e4d12014da84bffb1e845c2510e26b3c259ede9e42603cd6";
    create_and_transfer_v1(
        b"mysten1".to_string(),
        b"https://mysten-labs.com".to_string(),
        0,
        pk1,
        scenario.ctx(),
    );
    scenario.next_tx(addr1);
    let s1: KeyServer = scenario.take_from_sender();

    let pk2 =
        x"93b3220f4f3a46fb33074b590cda666c0ebc75c7157d2e6492c62b4aebc452c29f581361a836d1abcbe1386268a5685103d12dec04aadccaebfa46d4c92e2f2c0381b52d6f2474490d02280a9e9d8c889a3fce2753055e06033f39af86676651";
    create_and_transfer_v1(
        b"mysten2".to_string(),
        b"https://mysten-labs.com".to_string(),
        0,
        pk2,
        scenario.ctx(),
    );
    scenario.next_tx(addr1);
    let s2: KeyServer = scenario.take_from_sender();

    // Anyone can create a vote.
    let mut vote = create_vote(
        vector[@0x1, @0x2],
        vector[s0.id(), s1.id(), s2.id()],
        vector[pk0, pk1, pk2],
        2,
        scenario.ctx(),
    );

    // cargo run --bin seal-cli encrypt-hmac --message 0x07 --aad 0x0000000000000000000000000000000000000000000000000000000000000001 --package-id 0x0 --id 0x75c3360eb19fd2c20fbba5e2da8cf1a39cdb1ee913af3802ba330b852e459e05 --threshold 2 a58bfa576a8efe2e2730bc664b3dbe70257d8e35106e4af7353d007dba092d722314a0aeb6bca5eed735466bbf471aef01e4da8d2efac13112c51d1411f6992b8604656ea2cf6a33ec10ce8468de20e1d7ecbfed8688a281d462f72a41602161 a9ce55cfa7009c3116ea29341151f3c40809b816f4ad29baa4f95c1bb23085ef02a46cf1ae5bd570d99b0c6e9faf525306224609300b09e422ae2722a17d2a969777d53db7b52092e4d12014da84bffb1e845c2510e26b3c259ede9e42603cd6 93b3220f4f3a46fb33074b590cda666c0ebc75c7157d2e6492c62b4aebc452c29f581361a836d1abcbe1386268a5685103d12dec04aadccaebfa46d4c92e2f2c0381b52d6f2474490d02280a9e9d8c889a3fce2753055e06033f39af86676651 -- 0x34401905bebdf8c04f3cd5f04f442a39372c8dc321c29edfb4f9cb30b23ab96 0xd726ecf6f7036ee3557cd6c7b93a49b231070e8eecada9cfa157e40e3f02e5d3 0xdba72804cc9504a82bbaa13ed4a83a0e2c6219d7e45125cf57fd10cbab957a97
    // cargo run --bin seal-cli encrypt-hmac --message 0x2a --aad 0x0000000000000000000000000000000000000000000000000000000000000002 --package-id 0x0 --id 0x75c3360eb19fd2c20fbba5e2da8cf1a39cdb1ee913af3802ba330b852e459e05 --threshold 2 a58bfa576a8efe2e2730bc664b3dbe70257d8e35106e4af7353d007dba092d722314a0aeb6bca5eed735466bbf471aef01e4da8d2efac13112c51d1411f6992b8604656ea2cf6a33ec10ce8468de20e1d7ecbfed8688a281d462f72a41602161 a9ce55cfa7009c3116ea29341151f3c40809b816f4ad29baa4f95c1bb23085ef02a46cf1ae5bd570d99b0c6e9faf525306224609300b09e422ae2722a17d2a969777d53db7b52092e4d12014da84bffb1e845c2510e26b3c259ede9e42603cd6 93b3220f4f3a46fb33074b590cda666c0ebc75c7157d2e6492c62b4aebc452c29f581361a836d1abcbe1386268a5685103d12dec04aadccaebfa46d4c92e2f2c0381b52d6f2474490d02280a9e9d8c889a3fce2753055e06033f39af86676651 -- 0x34401905bebdf8c04f3cd5f04f442a39372c8dc321c29edfb4f9cb30b23ab96 0xd726ecf6f7036ee3557cd6c7b93a49b231070e8eecada9cfa157e40e3f02e5d3 0xdba72804cc9504a82bbaa13ed4a83a0e2c6219d7e45125cf57fd10cbab957a97

    // Cast votes. These have been encrypted using the Seal CLI.
    scenario.next_tx(@0x1);
    let encrypted_vote_1 =
        x"0000000000000000000000000000000000000000000000000000000000000000002075c3360eb19fd2c20fbba5e2da8cf1a39cdb1ee913af3802ba330b852e459e0503034401905bebdf8c04f3cd5f04f442a39372c8dc321c29edfb4f9cb30b23ab9601d726ecf6f7036ee3557cd6c7b93a49b231070e8eecada9cfa157e40e3f02e5d302dba72804cc9504a82bbaa13ed4a83a0e2c6219d7e45125cf57fd10cbab957a970302008b93486446666d2b58432f93a11a1e322c3bb6c492fca1ab892e9fd242aae343287a63e1d73b156e98a09c874e52bc520fe437590c092e8b9f0517e0143584463ba2ce3306e74f3f914617aa949114370a697354412f6e68f7d2850cb1a056560357ac9e1fae811a3249f07990a31e9d50a99adcc2422119fd3ea135054178255ec0194ca64905dc83dc68cc0b99b3ec0281ab72adc680d1711be74ed80702985d176431226b238b36789d76731bbebdaa9805fe3750c37b71101dbbc89873bb6e289d8e4829867e8f995d236de3ab779f8a995354c10835ea4ea6eab2f3b239640101a301200000000000000000000000000000000000000000000000000000000000000001d05b308cad3295c2264d2f49bcd2c461ff9c2d5acf8230f9405d70bbfe62b7a6";
    cast_vote(&mut vote, encrypted_vote_1, scenario.ctx());

    scenario.next_tx(@0x2);
    let encrypted_vote_2 =
        x"0000000000000000000000000000000000000000000000000000000000000000002075c3360eb19fd2c20fbba5e2da8cf1a39cdb1ee913af3802ba330b852e459e0503034401905bebdf8c04f3cd5f04f442a39372c8dc321c29edfb4f9cb30b23ab9601d726ecf6f7036ee3557cd6c7b93a49b231070e8eecada9cfa157e40e3f02e5d302dba72804cc9504a82bbaa13ed4a83a0e2c6219d7e45125cf57fd10cbab957a97030200acb9586ed1130a0c8455ed226da8d949a130d5eb6d97399da8b5575681ffe835e1293abc9a828313e5803abbb1ded25e123bc2164c54874a800002e5cb11a0a5d4679009f9e9b2306e777d8f2430183082a2d0cabedafcf4038f72c1a08f69aa039256d911b38c514ba81af8c0aa2dc02a48d385ec33a79cb78930bab020166b1dadb1dceb78cdcb8325a2bcefe7f9d32bfec35b2dc50b197aa01de2f94cb411b8a53983a8e93ee1c1a759d4d7900507c7ed492d0df09b3d66e51f3e31cd2d8ff40c83c7639964ceb73eec9b32c78a23ff51e90d95c88bbb6011a37161688749f00101960120000000000000000000000000000000000000000000000000000000000000000201e5444be569afe5c68978222ea0aa798f0a4e4047968cc74cdfe1cbd1a14a6c";
    cast_vote(&mut vote, encrypted_vote_2, scenario.ctx());

    // Both voters have now voted, so the vote is sealed and seal_approve will succeed.
    seal_approve(*parse_encrypted_object(encrypted_vote_1).id(), &vote);
    seal_approve(*parse_encrypted_object(encrypted_vote_2).id(), &vote);

    // The derived keys. These should have been retrieved from key servers. They can also be computed from the cli:
    // cargo run --bin seal-cli extract --package-id 0x0 --id 0x75c3360eb19fd2c20fbba5e2da8cf1a39cdb1ee913af3802ba330b852e459e05 --master-key 3c185eb32f1ab43a013c7d84659ec7b59791ca76764af4ee8d387bf05621f0c7
    let dk0 =
        x"a24161c1c8398aac9942aed38e9ad9c923f033f75f067f8a3a511f313d03e2b722671a01f20d9d56ae30913994190a5b";
    // cargo run --bin seal-cli extract --package-id 0x0 --id 0x75c3360eb19fd2c20fbba5e2da8cf1a39cdb1ee913af3802ba330b852e459e05 --master-key 09ba20939b2300c5ffa42e71809d3dc405b1e68259704b3cb8e04c36b0033e24
    let dk1 =
        x"b1ecf1d8da591deac2cf271048a327cb731809e0187ae8bcd54c79e92bf58c7b96e415eb1dbe62b6ced54de3197b249b";

    // Finalize vote
    assert!(vote.result.is_none());
    finalize_vote(
        &mut vote,
        &vector[dk0, dk1],
        &vector[s0.id(), s1.id()],
    );
    assert!(vote.result.is_some());

    // Voter 1 voted '7' and voter 2 voted '42'.
    assert!(vote.result.borrow()[0].borrow() == 7);
    assert!(vote.result.borrow()[1].borrow() == 42);

    // Clean up
    ks_destroy(s0);
    ks_destroy(s1);
    ks_destroy(s2);
    destroy_for_testing(vote);
    scenario.end();
}
