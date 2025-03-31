import { SealClient, SessionKey, NoAccessError, EncryptedObject } from "@mysten/seal";
import { SuiClient } from "@mysten/sui/client";
import React from 'react';

// A common interface for transaction params. 
interface BaseTxParams<T extends string, P extends Record<string, string>> {
  moduleName: T;
  params: P;
}

type AllowlistParams = BaseTxParams<"allowlist", { innerId: string }>;
type SubscriptionParams = BaseTxParams<"subscription", { 
  subscriptionId: string;
  serviceId: string;
}>;

export type TxParams = AllowlistParams | SubscriptionParams;

type TxBytesConstructor = (
  packageId: string,
  fullId: string,
  suiAddress: string,
  suiClient: SuiClient,
  txParams: TxParams
) => Promise<Uint8Array>;

export const handleDecryption = async (
  blobIds: string[],
  sessionKey: SessionKey,
  packageId: string,
  suiAddress: string,
  txParams: TxParams,
  suiClient: SuiClient,
  client: SealClient,
  constructTxBytes: TxBytesConstructor,
  setError: (error: string | null) => void,
  setDecryptedFileUrls: (urls: string[]) => void,
  setIsDialogOpen: (open: boolean) => void,
  setReloadKey: (updater: (prev: number) => number) => void,
) => {
  const aggregators = ["aggregator1", "aggregator2", "aggregator3"];
  // First, download all files in parallel (ignore errors)
  const downloadResults = await Promise.all(
    blobIds.map(async (blobId) => {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 10000); 
        const randomAggregator = aggregators[Math.floor(Math.random() * aggregators.length)];
        const aggregatorUrl = `/${randomAggregator}/v1/blobs/${blobId}`;        
        const response = await fetch(aggregatorUrl, { signal: controller.signal });
        clearTimeout(timeout);
        if (!response.ok) {
          return null;
        }
        return await response.arrayBuffer();
      } catch (err) {
        console.error(`Blob ${blobId} cannot be retrieved from Walrus`, err);
        return null;
      }
    })
  );

  // Filter out failed downloads
  const validDownloads = downloadResults.filter((result): result is ArrayBuffer => result !== null);
  console.log(`downloaded ${validDownloads.length} files out of ${blobIds.length}`);
  
  if (validDownloads.length === 0) {
    const errorMsg = "Cannot retrieve files from this Walrus aggregator, try again (a randomly selected aggregator will be used).";
    console.error(errorMsg);
    setError(errorMsg);
    return;
  }

  const decryptedFileUrls: string[] = [];

  // Then, decrypt files sequentially
  for (const encryptedData of validDownloads) {
    const fullId = EncryptedObject.parse(new Uint8Array(encryptedData)).id;
    const txBytes = await constructTxBytes(
      packageId,
      fullId,
      suiAddress,
      suiClient,
      txParams
    );
    try {
      const decryptedFile = await client.decrypt({
        data: new Uint8Array(encryptedData),
        sessionKey,
        txBytes,
      });
      const blob = new Blob([decryptedFile], { type: "image/jpg" });
      decryptedFileUrls.push(URL.createObjectURL(blob));      
    } catch (err) {
      console.log(err);
      const errorMsg = err instanceof NoAccessError
        ? "No access to decryption keys"
        : "Unable to decrypt files, try again";
      console.error(errorMsg, err);
      setError(errorMsg);
      return;
    }
  }
  
  if (decryptedFileUrls.length > 0) {
    setDecryptedFileUrls(decryptedFileUrls);
    setIsDialogOpen(true);
    setReloadKey(prev => prev + 1);
  }
};

export const getObjectExplorerLink = (id: string): React.ReactElement => {
  return React.createElement(
    'a',
    {
      href: `https://testnet.suivision.xyz/object/${id}`,
      target: '_blank',
      rel: 'noopener noreferrer',
      style: { textDecoration: 'underline' }
    },
    id.slice(0, 10) + '...'
  );
}; 