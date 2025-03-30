## Table of Contents:

- [Introduction](README.md)
- [Using Seal](UsingSeal.md)
- [Seal Beta Terms of Service](TermsOfService.md)

# Seal Design

### Overview

The system uses a cryptographic primitive called *Identity-Based Encryption (IBE)* to encrypt the stored data. This detail is hidden from the developers and users, as Seal is oblivious to the data it stores.

An [IBE scheme](https://en.wikipedia.org/wiki/Identity-based_encryption) consists of the following algorithms:
- `Setup`: Generates a master secret key `msk` and a master public key `mpk`.
- `Derive(msk, id)`: Given a master secret key and an identity `id` (string or byte array), generates a derived secret key `sk` for that identity.
- `Encrypt(mpk, id, m)`: Given a public key, an identity and a message, returns an encryption `c`.
- `Decrypt(sk, c)`: Given  a derived secret key and a ciphertext, compute the message `m`.
Such a scheme is correct if for any `id` and `m`, `(msk, mpk) ← Setup()` and `c ← Encrypt(mpk, id, m)` we have `Decrypt(Derive(msk, id, m), c) = m`.

Note that the domain of identities is *not* fixed, and can be any string/byte array.
We use that property below to bound onchain strings to IBE identities.

Seal consists of two main components:
- **Access policies defined on Sui:** A Move package at address `PkgId` controls the subdomain of IBE identities that starts with `[PkgId]` (i.e., all strings of the form `[PkgId]*`). One can think of `[PkgId]` as an identity *namespace*. A package defines in Move who can access the keys associated with its subdomain of identities.
- **Off-chain Key Servers:** Off-chain services, each holding a single IBE master secret key. Users can ask a key server to derive a secret key for an identity, and the server will return the derived secret key only if access is approved by the related on-chain policy.

Consider the following basic example for realizing time-lock encryption:
```move
module patterns::tle;

use sui::bcs;
use sui::clock;

const ENoAccess : u64 = 1;

/////////////////////////////////////////////
/// Access control
/// key format: [pkg id][bcs::to_bytes(time)]
entry fun seal_approve(id: vector<u8>, c: &clock::Clock) {
    // Convert the identity to u64.
    let mut prepared: BCS = bcs::new(id);
    let t = prepared.peel_u64();
    let leftovers = prepared.into_remainder_bytes();

    // Check that the time has passed and the entire identity is consumed.
    assert!((leftovers.length() == 0) && (c.timestamp_ms() >= t), ENoAccess);
}
```

The above module controls all IBE identities that begin with its package id `PkgId`. A user who wants to encrypt data with a time-lock `T` can choose a key-server and encrypt the data using identity `[PkgId][bcs::to_bytes(T)]` and the server's IBE master public key. Once the time on Sui is larger than `T`, *anyone* can query the Seal server for the key of identity `[PkgId][bcs::to_bytes(T)]`. This access control is implemented by the `seal_approve` function above, which receives the requested identity (without the `PkgId` prefix) and `Clock` as arguments, and succeeds only if the current time is at least `T`. The key-server locally evaluates `seal_approve` to decide whether to return the derived key or not.

Time-lock encryption can be used for various onchain applications, such as MEV-resistant trading, secure voting, etc.
See [move/patterns](./move/patterns) for more examples and useful patterns.

The framework is completely generic. Developers can implement any authorization logic inside `seal_approve*` functions and can decide which key-servers to use depending on their use case (e.g., whether to use a fixed set of servers, or, ask the user to choose its preferred servers).

Package upgrades maintain the same subdomain of identities, however only the latest version of the package can be used
for access control (i.e., only `seal_approve*` functions from the latest version of the package are evaluated). Note that as long as a package can be upgraded, the policy can be modified arbitrarily by the package owner (though transparently to everyone).

### Decentralization and trust model

Seal is designed to reduce centralization using a couple of mechanisms.

First, users may choose to use any set of one or more key servers and use their master public keys to encrypt their data. This can be used to realize `t-out-of-n` threshold encryption, providing privacy as long as less than `t` servers are compromised, and liveness as long as at least `t` servers are available. Seal does not require any specific key server to be used, and users can choose their preferred servers based on their trust assumptions. We expect different key servers to be deployed with different security properties (e.g., enclaves, or even air-gapped solutions), and in different locations and jurisdictions.

> [!NOTE]
> The set of key servers is **not** dynamic once the data is encrypted, and encrypted data cannot be changed to use a different set of servers.

Second, a single key server can itself be implemented using a MPC committee in a `t-out-of-n` fashion. This MPC committee can be formed by Sui validators, or any other set of participants. We expect such MPC key-servers to be deployed in the near future, and users could use them in addition to the standalone key store services. In this case, the set of parties that form the MPC committee can be dynamic.

Security of the encrypted data is based on the following assumptions:
- The Seal key servers are not compromised, or less than a threshold of them are compromised in case threshold encryption was used. This includes both the Seal Key servers and the Sui full nodes their rely on for evaluating the access policy.
- The policy associated with the encrypted data is correct. Note that a policy can be modifed by the package owner at any time if package upgrades are possible, and the new policy will replace the old one.

### Key Server
A light server that is initialized with an IBE master secret key, and has access to a full node (trusted by the service). Simple deployments can be of a backend server with secret key stored in protected storage. More sophisticated deployment may use enclaves, MPC committees, or even air-gapped solutions.

The server exposes only two APIs:
- `/v1/service` - Returns information about the service's onchain registered information.
- `/v1/fetch_key` - Receives a request for one or more derived keys and returns them if access is allowed by the related package/policies.
A request must be signed by the user's address using `signPersonalMessage` (see format at [signed_message](crates/key-server/src/signed_message.rs)), and include a PTB that is used for evaluating `seal_approve*`, and an encryption key to be used to encrypt the response. 
The PTB must be constructed as defined in [valid_ptb](./crates/key-server/src/valid_ptb.rs).
Encrypting the response guarantees that only the initiator can decrypt it.

See [crates/key-server](crates/key-server/src/server.rs) for the implementation of the key server.

### User confirmation and sessions
Decryption keys returned from the key server are returned directly to the caller, which is the dapp's web page in most cases.
To make sure that dapps can only access keys approved by the user, the user must aprove in its wallet the request to the key servers. The approval is done once for all the keys associated with a specific package, resulting in a `session key` that can be used by the dapp to access the keys for limited time without additional user confirmations.

### Cryptographic primitives
Seal is designed to be compatible with different IBE schemes as a Key Encapsulation Mechanism (KEM), and different symmetric encryption schemes as a Data Encapsulation Mechanism (DEM).
The currently supported primitives:
- KEM: Boneh-Franklin IBE with the BLS12-381 curve.
- DEM: AES-256-GCM, HMAC based CTR mode (to be used when onchain decryption is needed).

Post-quantum primitives are planned to be added in the future.

[Back to table of contents](#table-of-contents)
