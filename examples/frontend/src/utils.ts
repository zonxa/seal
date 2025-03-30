import { SealClient, SessionKey } from "@mysten/seal";
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
  try {
    // First, download all files in parallel
    const downloadResults = await Promise.all(
      blobIds.map(async (blobId) => {
        try {
          const response = await fetch(blobId);
          if (response.status === 404) {
            console.error(`Blob not found on Walrus: ${blobId}`);
            return null;
          }
          if (response.status === 403) {
            setError("No access to an encrypted file");
            return null;
          }
          if (!response.ok) {
            setError("Failed to fetch an encrypted file");
            return null;
          }
          return await response.arrayBuffer();
        } catch (err) {
          setError("Failed to fetch an encrypted file");
          return null;
        }
      })
    );

    // Filter out failed downloads
    const validDownloads = downloadResults.filter((result): result is ArrayBuffer => result !== null);
    
    if (validDownloads.length === 0) {
      return;
    }

    // Then, decrypt files sequentially (recall that the key is fetched once for all files)
    const decryptedFileUrls: string[] = [];
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
        if (err instanceof Error) {
          setError(err.message);
        } else {
          setError('An unknown error occurred');
        }
        // Continue with next file even if one fails
        continue;
      }
    }
    
    if (decryptedFileUrls.length > 0) {
      setDecryptedFileUrls(decryptedFileUrls);
      setIsDialogOpen(true);
      setReloadKey(prev => prev + 1);
    }
  } catch (err) {
    if (err instanceof Error) {
      setError(err.message);
    } else {
      setError('An unknown error occurred');
    }
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