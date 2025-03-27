// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
import { getFullnodeUrl } from "@mysten/sui/client";
import {
  DEVNET_PACKAGE_ID,
  TESTNET_PACKAGE_ID,
  MAINNET_PACKAGE_ID,
} from "./constants";
import { createNetworkConfig } from "@mysten/dapp-kit";

const { networkConfig, useNetworkVariable, useNetworkVariables } =
  createNetworkConfig({
    devnet: {
      url: getFullnodeUrl("devnet"),
      variables: {
        packageId: DEVNET_PACKAGE_ID,
        gqlClient: "https://sui-devnet.mystenlabs.com/graphql",
      },
    },
    testnet: {
      url: getFullnodeUrl("testnet"),
      variables: {
        packageId: TESTNET_PACKAGE_ID,
        gqlClient: "https://sui-testnet.mystenlabs.com/graphql",
      },
    },
    mainnet: {
      url: getFullnodeUrl("mainnet"),
      variables: {
        packageId: MAINNET_PACKAGE_ID,
        gqlClient: "https://sui-mainnet.mystenlabs.com/graphql",
      },
    },
  });

export { useNetworkVariable, useNetworkVariables, networkConfig };
