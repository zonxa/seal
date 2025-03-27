// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
import { useEffect, useState } from "react";
import { useSignPersonalMessage, useSuiClient } from "@mysten/dapp-kit";
import { useNetworkVariable } from "./networkConfig";
import { AlertDialog, Button, Card, Dialog, Flex, Grid } from "@radix-ui/themes";
import { fromHex, toHex } from "@mysten/sui/utils";
import { Transaction } from "@mysten/sui/transactions";
import { SuiClient } from "@mysten/sui/client";
import { getAllowlistedKeyServers, SealClient, SessionKey } from "@mysten/seal";
import { useParams } from "react-router-dom";

const TTL_MIN = 10;
export interface FeedData {
  allowlistId: string;
  allowlistName: string;
  blobIds: string[];
}
/**
 * Construct a ptb for the given package id, module name, sui address, sui client and inner id. This corresponds to `entry fun seal_approve` in `allowlist.move`.
 * 
 * @param packageId - The package id.
 * @param moduleName - The module name.
 * @param suiAddress - The sui address.
 * @param suiClient - The sui client.
 * @param innerId - The inner id.
 * @returns The transaction data bytes.
 */
async function constructTxBytes(packageId: Uint8Array, moduleName: string, suiAddress: string, suiClient: SuiClient, innerId: string): Promise<Uint8Array> {
  const tx = new Transaction();
  tx.setSender(suiAddress);
  tx.moveCall({
    target: `${toHex(packageId)}::${moduleName}::seal_approve`,
    arguments: [
      tx.pure.vector("u8", fromHex(innerId)),
      tx.object(innerId),
    ]
  });
  return await tx.build({ client: suiClient, onlyTransactionKind: true });
}

const Feeds: React.FC<{ suiAddress: string }> = ({ suiAddress }) => {
  const suiClient = useSuiClient();
  const client = new SealClient({
    suiClient,
    serverObjectIds: getAllowlistedKeyServers("testnet"),
  });
  const packageId = useNetworkVariable("packageId");

  const [feed, setFeed] = useState<FeedData>();
  const [decryptedFileUrls, setDecryptedFileUrls] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [currentSessionKey, setCurrentSessionKey] = useState<SessionKey | null>(null);
  const { id } = useParams();
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);

  const { mutate: signPersonalMessage } = useSignPersonalMessage();
  
  useEffect(() => {
    getFeed();
  }, [getFeed]);

  async function getFeed() {
    const allowlist = await suiClient.getObject({
      id: id!,
      options: { showContent: true },
    });
    const encryptedObjects = await suiClient.getDynamicFields({
      parentId: id!,
    }).then((res) => res.data.map((obj) => obj.name.value as string));
    const fields = (allowlist.data?.content as { fields: any })?.fields || {};
    const feedData = {
      allowlistId: id!,
      allowlistName: fields?.name,
      blobIds: encryptedObjects
    };
    setFeed(feedData);
  }

  const handleDecryption = async (
    blobIds: string[],
    sessionKey: SessionKey,
    txBytes: Uint8Array,
  ) => {
    const decryptedFileUrls = [];
    for (const blobId of blobIds) {
        // Fetch the blob from blobId
        const response = await fetch(blobId);
        if (response.status === 404) {
          console.error(`Blob not found on Walrus: ${blobId}`);
          continue;
        }
        if (response.status === 403) {
          throw new Error("Access forbidden");
        }
        if (!response.ok) {
          throw new Error("Network response was not ok");
        }

      try {
        const decryptedFile = await client.decrypt(
          {
            data: new Uint8Array(await response.arrayBuffer()),
            sessionKey,
            txBytes,
          }
        );
        const blob = new Blob([decryptedFile], { type: "image/jpg" });
        const decryptedFileUrl = URL.createObjectURL(blob);
        decryptedFileUrls.push(decryptedFileUrl);
      } catch (err) {
        if (err instanceof Error) {
          setError(err.message);
        } else {
          setError('An unknown error occurred');
        }
      }
    }
    setDecryptedFileUrls(decryptedFileUrls);
    setIsDialogOpen(true);
    setReloadKey(prev => prev + 1);
  }
  const onView = async (
    blobIds: string[],
    allowlistId: string,
  ) => {
    const txBytes = await constructTxBytes(
      fromHex(packageId),
      "allowlist",
      suiAddress,
      suiClient,
      allowlistId,
    );
    if (currentSessionKey && !currentSessionKey.isExpired() && currentSessionKey.getAddress() === suiAddress) {
      handleDecryption(blobIds, currentSessionKey, txBytes);
      setReloadKey(prev => prev + 1);
      return;
    }
		const sessionKey = new SessionKey({
			address: suiAddress,
			packageId,
			ttlMin: TTL_MIN,
		});

    setCurrentSessionKey(sessionKey);
    try {
      signPersonalMessage(
        {
          message: sessionKey.getPersonalMessage(),
        },
        {
          onSuccess: async (result) => {
            sessionKey.setPersonalMessageSignature(result.signature);
            handleDecryption(blobIds, sessionKey, txBytes);
            setReloadKey(prev => prev + 1);
          },
        },
      );
    } catch (error: any) {
      console.error("Error:", error);
    }
  };

  return (
    <Card>
      <h3>Files for Allowlist {feed?.allowlistName} (ID {feed?.allowlistId})</h3>
      {feed === undefined ? (
        <p>No files found for this allowlist.</p>
      ) : (
        <Grid columns="2" gap="3">
          <Card key={feed!.allowlistId}>
            <Flex direction="column" align="start" gap="2">
              {feed!.blobIds.length === 0 ? (
                <p>No files found for this allowlist.</p>
              ) : (
                <Dialog.Root open={isDialogOpen} onOpenChange={setIsDialogOpen}>
                <Dialog.Trigger>
                <Button 
                    onClick={() => onView(feed!.blobIds, feed!.allowlistId)}
                  >
                    Download And Decrypt All Files
                  </Button>
                </Dialog.Trigger>
                {decryptedFileUrls.length > 0 && (
                  <Dialog.Content maxWidth="450px" key={reloadKey}>
                  <Dialog.Title>View all files</Dialog.Title>
                    <Flex direction="column" gap="2">
                    {
                      decryptedFileUrls.map((decryptedFileUrl, index) => (
                        <div key={index}>
                          <img
                            src={decryptedFileUrl}
                            alt={`Decrypted image ${index + 1}`}
                            />
                          </div>
                        ))
                      }
                    </Flex>
                  <Flex gap="3" mt="4" justify="end">
                    <Dialog.Close>
                      <Button variant="soft" color="gray" onClick={() => setDecryptedFileUrls([])}>
                        Close
                      </Button>
                    </Dialog.Close>
                  </Flex>
                  </Dialog.Content>
                )}
              </Dialog.Root>
              )}
            </Flex>
          </Card>
        </Grid>
      )}
      <AlertDialog.Root open={!!error} onOpenChange={() => setError(null)}>
        <AlertDialog.Content maxWidth="450px">
          <AlertDialog.Title>Error</AlertDialog.Title>
          <AlertDialog.Description size="2">
            No access to this feed.
          </AlertDialog.Description>

          <Flex gap="3" mt="4" justify="end">
            <AlertDialog.Action>
              <Button variant="solid" color="gray" onClick={() => setError(null)}>
                Close
              </Button>
            </AlertDialog.Action>
          </Flex>
        </AlertDialog.Content>
      </AlertDialog.Root>
    </Card>
  );
};

export default Feeds;
