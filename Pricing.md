## Table of Contents:

- [Introduction](README.md)
- [Seal Design](Design.md)
- [Using Seal](UsingSeal.md)
- [Security Best Practices and Risk Mitigations](SecurityBestPractices.md)
- [Seal Beta Terms of Service](TermsOfService.md)

# Seal pricing

- **Choose your own key server providers:** Seal supports a decentralized network of independent key servers. Builders can select any combination of providers to form their preferred threshold configuration for encryption and decryption.
- **Transparent pricing & features:** Each key server provider sets their own pricing and rate limits based on their service model. Builders can evaluate and choose based on what best fits their application needs.
- **Curated discoverability:** This documentation will list a verified set of providers along with available links to their configuration details, terms, and pricing, so you can integrate with confidence.

## Verified key servers

Please refer to [this document](UsingSeal.md#for-key-server-operators) for detailed information on `Open` and `Permissioned` modes of key servers. At a high-level:

- A key server in `Open` mode lets anyone request keys for any access policy package, using a shared master key. It is ideal for public or trial use. 
- A key server in `Permissioned` mode restricts access to approved access policy packages per client, each with a dedicated master key, and supports secure key server rotation or switching when needed. It is designed for dedicated or commercial use.

### Testnet

- Mysten Labs: The following key servers are configured using the `Open` mode and freely available for experimentation, development, and testing. A source-based rate limit is configured which can not be changed for any client.
    - mysten-testnet-1: https://seal-key-server-testnet-1.mystenlabs.com
    - mysten-testnet-2: https://seal-key-server-testnet-2.mystenlabs.com
- [Ruby Nodes](https://seal.rubynodes.io):
    - `Open` mode
        - URL: https://free-eu-central-1.api.rubynodes.io 
        - Object Id: `0x781389fae54633649d78b731b708c5b363cf7fa4753a48997d4f6f82d5cc5b98`
    - `Permissioned` mode
        - URL: https://starter-eu-central-1.api.rubynodes.io
        - Contact the provider to configure your client and generate a unique key server object id
- [NodeInfra](https://nodeinfra.com/):
    - `Open` mode
        - URL: https://open-seal-testnet.nodeinfra.com
        - Object Id: `0x5466b7df5c15b508678d51496ada8afab0d6f70a01c10613123382b1b8131007`
    - `Permissioned` mode
        - URL: https://seal-testnet.nodeinfra.com
        - Contact the provider to configure your client and generate a unique key server object id
- Studio Mirai:
    - `Open` mode
        - URL: https://public.key-server.testnet.seal.mirai.cloud
        - Object Id: `0x27cf65cfd514e9fad1211c2f6e164b59c000be43466088faeb4a65952b6bfb99`
    - `Permissioned` mode
        - URL: https://private.key-server.testnet.seal.mirai.cloud
        - Contact the provider to configure your client and generate a unique key server object id

> [!NOTE]
> Testnet key servers are provided for developer testing only and do not come with availability guarantees, SLAs, or assurances regarding long-term key persistence. Please avoid using them to encrypt data you expect to access reliably in the future.

### Mainnet

Coming soon

[Back to table of contents](#table-of-contents)