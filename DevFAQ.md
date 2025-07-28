## Table of Contents:

- [Introduction](README.md)
- [Seal Design](Design.md)
- [Using Seal](UsingSeal.md)
- [Security Best Practices and Risk Mitigations](SecurityBestPractices.md)
- [Pricing](Pricing.md)
- [Seal Beta Terms of Service](TermsOfService.md)

# Developer FAQs

> [!TIP]
> Refer to the [Security Best Practices and Risk Mitigations](SecurityBestPractices.md) as well.

## How do I define and deploy a Seal access policy in Move?

You define one or more `seal_approve*` entry functions in your Move module. Start the function with an argument that represents the requesting identity (such as `id: vector<u8>`). You can define multiple such functions with different logic and inputs. Follow the versioning best practices using shared objects. Refet to [Move patterns](./move/patterns/) to get started.

## What should I avoid when writing `seal_approve*` functions?

Avoid using frequently changing state (like counters), assuming transaction order, relying on randomness, or introducing side effects. Seal evaluates these functions using `dry_run_transaction_block`, which reads slightly different states across Sui Full nodes. Keep logic deterministic and self-contained.

## How do I encrypt data using the Seal SDK?

First, initialize a `SealClient` with your selected key server configuration. Then call `encrypt()` with:

- The encryption threshold
- Your access policy’s `packageId`
- The `id` representing the requesting identity
- The data you want to encrypt

The SDK performs threshold identity-based encryption and returns the encrypted object along with a backup symmetric key.

## How do I decrypt data using the Seal SDK?

First, create a `SessionKey` and generate a signature for the authorization message. In most cases, prompt the user to sign this message using their wallet, ensuring explicit consent and secure access delegation.

In rare cases, such as for automated workflows or admin-initiated access, you can use a managed application key pair to sign on behalf of the user. If you choose this approach, make sure to clearly communicate it to your users through documentation, in-product messaging, or another accessible mechanism. It’s important to ensure users understand who is authorizing access on their behalf.

After setting the signature on the `SessionKey`, build a Sui `Transaction` that calls the relevant `seal_approve*` function. Then call `decrypt()` with the encrypted data, session key, and transaction block to retrieve the decrypted content.

## Can I reuse the same encrypted content with updated access policies over time?

Yes. You can encrypt your content once using an ephemeral symmetric key, then encrypt that key using Seal. This setup allows you to change access by updating the onchain access policy or rotating key servers, without needing to re-encrypt the underlying content. This approach works especially well for long-lived assets - like gated documents, media, or datasets - where access conditions may evolve over time.

## How can I persist a user’s session for multiple decryptions without re-signing?

You can store the `SessionKey` in `IndexedDB` or export and re-import it between sessions. This lets the user decrypt multiple items in a session (e.g., 10 minutes) without needing to sign each time.

## How do I choose between `Open` and `Permissioned` key servers?

Choose `Open` mode for testing, prototyping, or public-access apps where you don’t need custom isolation. Use `Permissioned` mode for production deployments that need per-client configurations, onchain package restrictions, and safer key rotation.

Refer to the [verified key servers](Pricing.md#verified-key-servers) for a list of available key servers in different environments.

## How do I verify key servers and prevent impersonation?

Use the SDK’s built-in verification: enable `verifyKeyServers: true` when initializing `SealClient`. This setting fetches the `/v1/service` endpoint from each key server and checks that the object ID matches the registered onchain key server. Always verify URLs against their onchain identity.

## Why should I assign weights to key servers?

Assigning weights lets you control how much influence each key server has toward reaching the decryption threshold. For example, you can give your most trusted or highly available servers higher weights to ensure they contribute more consistently.

## How do I optimize performance when decrypting multiple items?

Use the `fetchKeys()` function and pass a PTB that includes multiple `seal_approve` calls. This approach minimizes the number of HTTP calls to key servers and helps you avoid hitting rate limits while speeding up batch decryption.
