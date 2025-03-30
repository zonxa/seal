import { SealClient, SessionKey, NoAccessError } from "@mysten/seal";
import React from 'react';

export const handleDecryption = async (
  blobIds: string[],
  sessionKey: SessionKey,
  txBytes: Uint8Array,
  client: SealClient,
  setError: (error: string | null) => void,
  setDecryptedFileUrls: (urls: string[]) => void,
  setIsDialogOpen: (open: boolean) => void,
  setReloadKey: (updater: (prev: number) => number) => void,
) => {
  // First, download all files in parallel (ignore errors)
  const downloadResults = await Promise.all(
    blobIds.map(async (blobId) => {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 10000);
        const response = await fetch(blobId, { signal: controller.signal });
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
    const errorMsg = "Cannot retrieve files from Walrus";
    console.error(errorMsg);
    setError(errorMsg);
    return;
  }

  const decryptedFileUrls: string[] = [];

  // Then, decrypt files sequentially
  for (const encryptedData of validDownloads) {
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