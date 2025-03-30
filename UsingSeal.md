## Table of Contents:

- [Introduction](README.md)
- [Seal Design](Design.md)
- [Seal Beta Terms of Service](TermsOfService.md)

# Using Seal

## For Dapp Developers

**Access control management**

Packages should define `seal_approve*` functions in their modules to control access to the keys associated with their namespace of identities:
- There can be multiple `seal_approve*` functions in a package, and each function can have different access control logic and input parameters.
- The first parameter of `seal_approve*` functions must be the requested identity without the package ID prefix (e.g., `id: vector<u8>`).
- `seal_approve*` functions should abort if access is not granted, and not return any value.
- Preferably, `seal_approve*` functions should be defined as non-public `entry` functions, to support future upgrades without breaking backward compatibility.

See [move/patterns](./move/patterns) for examples and useful patterns.

As `seal_approve*` functions are standard Move functions, they can be tested locally using Move tests.
Building and publishing the code can be done using the [`Sui CLI`](https://docs.sui.io/references/cli), e.g.,: 
```shell
cd examples/move
sui move build
sui client publish --gas-budget 100000000
```

**Limitations**

`seal_approve*` functions are evaluated on full nodes using the `dry_run_transaction_block` RPC call, which in turn, executes the Move code with its internal state of the chain.
As full nodes execute transactions independently, different full nodes may evaluate `dry_run_transaction_block` differently.
Specifically, developers should be aware that:
- Changes to the onchain state may take time to propagate, and full nodes may not have the latest state.
- `seal_approve*` functions are not evaluated atomically on the same state on all key servers. Access by a specific user should not depend on a state that changes very frequantly as different full nodes may see different versions of the chain.
- `seal_approve*` functions must not rely on invariants that depend on the relative order of transactions in a checkpoint. E.g., in the following code, the intermediate values of the counters may be different on different full nodes since the execution of their `increment` operations may be interleaved.

```move

struct Counter {
    id: UID,
    count: u64,
}

public fun increment(counter: &mut Counter) {
    counter.count = counter.count + 1;
}

entry fun seal_approve(id: vector<u8>, cnt1: &Counter, cnt2: &Counter) {
    assert!(cnt1.count == cnt2.count, ENoAccess);
    ...
}
```

- `seal_approve*` functions cannot change the state (they should be side-effect free).
- While `Random` is available to `seal_approve*` functions, the value it returns is not secure and not deterministic among different full nodes, and should not be used.
- During Seal evaluation, only `seal_approve*` functions can be called directly, thus they should not assume composition with other PTB commands.


**Encryption and decryption**

The recommended way for encrypting and decrypting data is to use the [Seal SDK](https://www.npmjs.com/package/@mysten/seal).

First, the app should decide on the set of key servers to use.
Key servers register onchain their name, public key and URL by creating a `KeyServer` object. 
Referring to a key server is done with the object id of its `KeyServer`.

The common option for app developers is to use a fixed set of key servers that are pre-configured in their app.
Alternatively, the app can use a dynamic set of key servers, e.g., chosen by the user. 
In that case, the app should show the user the list of key servers and their URLs, and once the user selects the key servers to use, the app should verify that the provided URLs indeed link to the claimed key servers, see code below.
(Note that anyone can create an onchain `KeyServer` object that points to, for example, `seal.mystenlabs.com`, but with a different public key. Thus during verification, the SDK fetches the object id from the published URL's endpoint `/v1/service` and compares it with the one of the onchain object, to protect against impersonation.)
An app can retrieve the object ids of the allowlisted Seal key servers using 
`getAllowlistedKeyServers()`, or alternatively an app/user defined list.

Next, the app should create a `SealClient` object for the selected key servers.
```typescript
const suiClient = new SuiClient({ url: getFullnodeUrl('testnet') });
const client = new SealClient({
    suiClient,
    serverObjectIds: keyServerIds,
    verifyKeyServers: false,
});
```

`verifyKeyServers` should be set to `true` if the app/user needs to verify that the provided URLs indeed link to the claimed key servers as discussed above.
(Note that verification requires additional round-trips to the key servers, and preferably should be used when the app/user needs to verify the key servers on startup, and `false` otherwise.)

Next, the app can call `encrypt` of `client` with the threshold, package id of the deployed contract with the `seal_approve*` functions,
the id that corresponds to the policy, and the data to be encrypted.
This function returns the encrypted object and the symmetric key used for encryption (i.e., the key of the DEM component of the KEM/DEM encryption).
The latter can be ignored, or returned to the user as a backup for disaster recovery.

```typescript
const { encryptedObject: encryptedBytes, key: backupKey } = await client.encrypt({
    threshold: 2,
    packageId: fromHEX(packageId),
    id: fromHEX(id),
    data,
});
```

Note that the encryption does **not** hide the message size. 
In case the message size is sensitive, one should append zeros to the message until the length does not reveal sensitive information.

> [!NOTE]
> One may use Seal to encrypt an ephemeral symmetric key that is used to encrypt the actual data. This can be useful for example for storing the encrypted content as an immutable data on Walrus, while storing the encrypted ephemeral key on Sui, allowing it to be changed over time (e.g., to use different key servers).

Decryption is a more involved process.
First, the app should create a `SessionKey` object for accessing the keys of a specific package.
The user should confirm providing time-limited access to the keys by signing the request in the wallet.
The resulting signature should be stored by the session key to complete its initialization.
An initialized session key can be used for retrieving multiple decryption keys for the specific package without additional user confirmations.
```typescript
const sessionKey = new SessionKey({
    address: suiAddress,
    packageId: fromHEX(packageId),
    ttlMin: 10, // TTL of 10 minutes
});
const message = sessionKey.getPersonalMessage();
const { signature } = await keypair.signPersonalMessage(message); // User confirms in wallet
sessionKey.setPersonalMessageSignature(signature); // Initialization complete
```

The simplest way to decrypt is to call the client’s
`decrypt` function. 
 This funtion expects a `Transaction` object that calls the relevant `seal_approve*` functions.
This transaction must only call `seal_approve*` functions, and only from the same package.

```typescript
// Create the Transaction for evaluating the seal_approve function.
const tx = new Transaction();
tx.moveCall({
    target: `${packageId}::${moduleName}::seal_approve`, 
    arguments: [
        tx.pure.vector("u8", fromHEX(id)),
        // other arguments
   ]
 });  
const txBytes = tx.build( { client: suiClient, onlyTransactionKind: true })
const decryptedBytes = await client.decrypt({
    data: encryptedBytes,
    sessionKey,
    txBytes,
});
```

Keys retrieved from Seal key servers are cached by `SealClient` for following decryptions (in case the same id is used by multiple encryptions).
In addition, multiple keys can be retrieved in a batch and stored in the cache by calling the function `fetchKeys` with a multi-command PTB. This option is recommended when multiple keys are needed, to reduce the number of calls to Seal key servers.
Since requests may be rate limited by key servers, developers are encouraged to design their applications and policies to minimize the number of requests.

```typescript
await client.fetchKeys({
    ids: [id1, id2],
    txBytes: txBytesWithTwoSealApproveCalls,
    sessionKey,
    threshold: 2,
});
```

See our [integration tests](https://github.com/MystenLabs/ts-sdks/blob/main/packages/seal/test/unit/integration.test.ts) for an E2E example.
Also, see our [example app](https://seal-example.vercel.app/) for a demonstration of allowlist/NFT gated content access.

On-chain decryption in Move is available as well given the derived keys.
See [voting.move](./move/patterns/sources/voting.move) for an example.

**Mysten Labs Key Servers**

Mysten Labs maintains a set of key servers for the Seal project:
- mysten-testnet-1: https://seal-key-server-testnet-1.mystenlabs.com
- mysten-testnet-2: https://seal-key-server-testnet-2.mystenlabs.com

While current access is permissive, rate-limiting requests to those servers is planned in the near future, targeting 1-2 requests per second per user.

## For key server operators

### Setup
Use the `seal-cli` tool to generate a new master key using `cargo run --bin seal-cli genkey`.

Key servers can be registered onchain to allow discoverability. The registration is done by calling the `register_and_transfer` function in the `seal::key_server` module, e.g.,
```shell
sui client call --function register_and_transfer --module key_server --package 0xa7e6441835fcdead3242b3e083c4f2886a32d4dffb2dddab2eb80ed201a4df9b --args mysten-dev-1 https://seal-key-server-testnet-1.mystenlabs.com 0xa023acbf600401017ee17bf918106ea9911914ca017aa3ab9ab5c64beb9bb5236fd9d4d5b5645dc3bc0d4f732ed04fc60d14b9f37987fe5eeb4db07fc0982904ce1ed0b07607ae2e99086e141f6c6a1df6def5f5d434ca7c09856a3750c92969 --gas-budget 10000000
```

Run the server using `cargo run --bin key-server` with environment variables:
- `MASTER_KEY` is the master secret key generated by the `seal-cli` tool.
- `KEY_SERVER_OBJECT_ID` is the object id of the registered key server.
- `NETWORK` is the network to connect to, e.g., `testnet`, `mainnet`, etc. Use the value `custom` for working with your own full node. In this case, the  variables `NODE_URL` and `GRAPHQL_URL` must be set as well with the URLs of the full node and the graphql endpoint, respectively. (Note that the GraphQL dependency will be removed in the future.)

Example:
```shell
export MASTER_KEY="KYinoC5hVWeWqOUU9dw7PVHiROYFWB/nQZ55Kmytjig="
export KEY_SERVER_OBJECT_ID="0x1ee708e0d09c31593a60bee444f8f36a5a3ce66f1409a9dfb12eb11ab254b06b"
export NETWORK="testnet"
cargo run --bin key-server
```

Alternativelly Docker can be used to run the key server, e.g.,
```shell
docker build -t seal-key-server .
docker run -p 2024:2024 -e MASTER_KEY="KYinoC5hVWeWqOUU9dw7PVHiROYFWB/nQZ55Kmytjig=" -e KEY_SERVER_OBJECT_ID="0x1ee708e0d09c31593a60bee444f8f36a5a3ce66f1409a9dfb12eb11ab254b06b" -e NETWORK="testnet" seal-key-server
```
<!-- 
Example of a request:
```
curl http://0.0.0.0:2024/health

curl http://0.0.0.0:2024/v1/service

curl -H 'Content-Type: application/json' -d '{"ptb":"AwAgv7n4Pj/owIGk+nMEXJ4KbXvVytgdurspb4BZJ8RdY6MAISDAbM35ybJGgprxCy0H1MuWKsGvRO5zQfk4jn+oAcufAwEBwGzN+cmyRoKa8QstB9TLlirBr0Tuc0H5OI5/qAHLnwOtCKsRAAAAAAABAG0lMvMLkGCIOUyRinodOfXWx1Bxm0JCFS/6RhBLoEUxCXdoaXRlbGlzdAtrbXNfYXBwcm92ZQADAQAAAQEAAQIA","enc_key":"lR69cNXFuB3zyjDI12syH1XC4sfaTo63Ylms/I8yO39OTvuDmngPln8pMTJEwq9v","request_signature":"Ut6iy+f+l/FeMgcim+s3jkQO86nxgqhWweOfqFWwQGi3gercjBnzhoMmzrb0i0Z79iXUwE56GwM/2mgHDRz+CA==","certificate":{"session_vk":"w+xC1R2fZDJeQW4lERxYsd3XVAYy7wOx5sKsIWdwlWw=","creation_time":1737671115293,"ttl_min":9,"signature":"APDPqXOr+HqHMw48qNwDMPezgvwDzojcIaBztBdOYuTaomY2pWBVyXbaFyNN+huz5f44ZgMG1D6PnF/H/OGgkADgFHRr36qyRWIXLGJ/iArkqpw1lMzlikMeDlBjTOheIw=="}}' -X POST http://0.0.0.0:2024/v1/fetch_key
``` -->

Key servers expose a set of metrics via a Prometheus server running on port 9184. They can be viewed in raw form by calling
```shell
curl http://0.0.0.0:9184
```
or used in a data visualization and analytics tool like Grafana.

### Infrastructure requirements

The key server is a lightweight service. It does not require storage and is stateless, allowing for horizontal scalability.
However, it does require access to a trusted Full Node, preferably one that is nearby to minimize latency.

The key server is initialized with an IBE master key, which should be securely stored and accessible only to the service (e.g., using a cloud KMS). Additionally, standard mitigations against denial-of-service attacks should be implemented to protect the service (e.g., rate limiting at the API gateway).


## The CLI

We provide a CLI tool `seal-cli` for generating keys, encrypting and decrypting messages.
In the following we demonstrate how to use the CLI to encrypt and decrypt messages.

First, we generate three random key pairs.
In Seal, these would be held by three different key servers by running `cargo run --bin seal-cli genkey`.
The output is random and will be different each time, but for this demo, we assume that we get the following three outputs:
```shell
Masterkey: 6b2eb410ad729f5b2ffa54ca5a2186ef95a1e31df3cccdd346b24f2262279440
Publickey: aeb258b9fb9a2f29f74eb0a1a895860bb1c6ba3f9ea7075366de159e4764413e9ec0597ac9c0dad409723935440a45f40eee4728630ae3ea40a68a819375bba1d78d7810f901d8a469d785d00cfed6bd28f01d41e49c5652d924e9d19fddcf62

Masterkey: 54152de3b08708b18ce5cd69b0c4d732f093cba2ba5c102c4f26e0f210daab75
Publickey: b1076a26f4f82f39d0e767fcd2118659362afe40bce4e8d553258c86756bb74f888bca79f2d6b71edf6e25af89efa83713a223b48a19d2e551897ac92ac7458336cd489be3be025e348ca93f4c94d22594f96f0e08990e51a7de9da8ff29c98f

Masterkey: 2ea9ccdaa224e9fc34ef1458fced17562b2d3757c1ebb223c627173ac6f93806
Publickey: 95fcb465af3791f31d53d80db6c8dcf9f83a419b2570614ecfbb068f47613da17cb9ffc66bb052b9546f17196929538f0bd2d38e1f515d9916e2db13dc43e0ccbd4cb3d7cbb13ffecc0b68b37481ebaaaa17cad18096a9c2c27a797f17d78623
```

For this example, assume that the onchain object ids for the three `KeyServer`s are `0x1`, `0x2`, and `0x3` respectively.
Also, assume that the package id is `0x0` and the threshold in use is 2.
Using the above public keys, we can now encrypt the message `54686520646966666572656e6365206265747765656e2061204d697261636c6520616e64206120466163742069732065786163746c792074686520646966666572656e6365206265747765656e2061206d65726d61696420616e642061207365616c` under the id `53e66d756e6472206672f3f069`.  

```shell
cargo run --bin seal-cli encrypt --message 54686520646966666572656e6365206265747765656e2061204d697261636c6520616e64206120466163742069732065786163746c792074686520646966666572656e6365206265747765656e2061206d65726d61696420616e642061207365616c --package-id 0x0 --id 53e66d756e6472206672f3f069 --threshold 2 aeb258b9fb9a2f29f74eb0a1a895860bb1c6ba3f9ea7075366de159e4764413e9ec0597ac9c0dad409723935440a45f40eee4728630ae3ea40a68a819375bba1d78d7810f901d8a469d785d00cfed6bd28f01d41e49c5652d924e9d19fddcf62 b1076a26f4f82f39d0e767fcd2118659362afe40bce4e8d553258c86756bb74f888bca79f2d6b71edf6e25af89efa83713a223b48a19d2e551897ac92ac7458336cd489be3be025e348ca93f4c94d22594f96f0e08990e51a7de9da8ff29c98f 95fcb465af3791f31d53d80db6c8dcf9f83a419b2570614ecfbb068f47613da17cb9ffc66bb052b9546f17196929538f0bd2d38e1f515d9916e2db13dc43e0ccbd4cb3d7cbb13ffecc0b68b37481ebaaaa17cad18096a9c2c27a797f17d78623 -- 0x1 0x2 0x3
```

which gives an output like the following:
```shell
Encrypted object (bcs): 0000000000000000000000000000000000000000000000000000000000000000000d53e66d756e6472206672f3f069030000000000000000000000000000000000000000000000000000000000000001e60000000000000000000000000000000000000000000000000000000000000002ba0000000000000000000000000000000000000000000000000000000000000003fb0200957db6826f49ab6cf56dcb9c77f98d0647c1e0ddd44d431bac774c97496a621c644649054ebde642f26f0877fd3e8adf0673012f3ffe07897031b9c168d50c3ef8da8ed3b09431314b6728d669619f9408a8ecaf86f5c658fa4e0a20df473caf035644301f023f47ba771d82754528ad3cb8bf1e1acb849155ccb59f6bb691579a6f9e8d787ffdd2571c84c9351328f17930aeb1ae240ac419de5bc471e8ebdc2569e564d4e66869f0ba56d430d5acb559876e2546365b512d8a75fb1ab3eb748d00721f6a07f3da5860f922946ffc2f93ddf01996cf853206e89851c6a0181d8076d2820797101a3a4fc9cc08d9dfaa7e4e02a9e3d877b383307ea6d801bbc3d694b856645e7ffcc8771776faadf3d5e44ddf67e747a9e1deb56814ea4d3fefa62f604635677edbc4cdb548a871d5f3db0dce1ebe00
Symmetric key: 0c5de1b6a70c1b8c6cc625b2dc98b765239cfaa79f6e1350e145ff386caf89f5
```
Note that the output contains both the encrypted object in BCS format and the symmetric key, that was used to encrypt the message.
The encrypted object can be shared, e.g., onchain or using Walrus, but the symmetric key should be kept secret (or ignored).

Next, to decrypt the message, we extract user secret keys for the key servers using their master keys. (In practice those would be retrieved from the key servers as described above.)
For the first key server, the command is as follows:
```shell
cargo run --bin seal-cli extract --package-id 0x0 --id 53e66d756e6472206672f3f069 --master-key 6b2eb410ad729f5b2ffa54ca5a2186ef95a1e31df3cccdd346b24f2262279440
```
and doing this for all three servers, we get the following outputs:
```shell
User secret key: b882fccc1f021c3b995e63a1f7329fcf71f750844195125e6a6b319dde9a7afc24b0c1a29d5a55f5908cf440dd7b3da3

User secret key: 97c30ec9dd6dafa187b732004a4d33414446115af35a1b1c0eb78af094f6e0d4d06830d5d7be9140cbcb05c63aaf7e28

User secret key: 8547bf7a70f7c1f3ad4070af8bc969f4afb82eddfcdca129fcedd6b7df1c91527ccd8d35dd33d0552cd95ba302ee6166
```

Using these extracted keys, we can now decrypt the encrypted object. Since we set the threshold to 2, we need to provide the keys from two servers, and here, we use the first two. 
```shell
cargo run --bin seal-cli decrypt 0000000000000000000000000000000000000000000000000000000000000000000d53e66d756e6472206672f3f069030000000000000000000000000000000000000000000000000000000000000001e60000000000000000000000000000000000000000000000000000000000000002ba0000000000000000000000000000000000000000000000000000000000000003fb0200957db6826f49ab6cf56dcb9c77f98d0647c1e0ddd44d431bac774c97496a621c644649054ebde642f26f0877fd3e8adf0673012f3ffe07897031b9c168d50c3ef8da8ed3b09431314b6728d669619f9408a8ecaf86f5c658fa4e0a20df473caf035644301f023f47ba771d82754528ad3cb8bf1e1acb849155ccb59f6bb691579a6f9e8d787ffdd2571c84c9351328f17930aeb1ae240ac419de5bc471e8ebdc2569e564d4e66869f0ba56d430d5acb559876e2546365b512d8a75fb1ab3eb748d00721f6a07f3da5860f922946ffc2f93ddf01996cf853206e89851c6a0181d8076d2820797101a3a4fc9cc08d9dfaa7e4e02a9e3d877b383307ea6d801bbc3d694b856645e7ffcc8771776faadf3d5e44ddf67e747a9e1deb56814ea4d3fefa62f604635677edbc4cdb548a871d5f3db0dce1ebe00 b882fccc1f021c3b995e63a1f7329fcf71f750844195125e6a6b319dde9a7afc24b0c1a29d5a55f5908cf440dd7b3da3 97c30ec9dd6dafa187b732004a4d33414446115af35a1b1c0eb78af094f6e0d4d06830d5d7be9140cbcb05c63aaf7e28 -- 0x1 0x2
```
which should give the following output:
```shell
Decrypted message: 54686520646966666572656e6365206265747765656e2061204d697261636c6520616e64206120466163742069732065786163746c792074686520646966666572656e6365206265747765656e2061206d65726d61696420616e642061207365616c
```
which, as expected, is the same as the original message.

[Back to table of contents](#table-of-contents)