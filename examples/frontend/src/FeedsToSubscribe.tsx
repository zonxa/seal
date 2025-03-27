// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
import { useEffect, useState } from "react";
import { useCurrentAccount, useSignAndExecuteTransaction, useSignPersonalMessage, useSuiClient } from "@mysten/dapp-kit";
import { useNetworkVariable } from "./networkConfig";
import { AlertDialog, Button, Card, Dialog, Flex, Heading } from "@radix-ui/themes";
import { SuiClient } from "@mysten/sui/client";
import { coinWithBalance, Transaction } from "@mysten/sui/transactions";
import { fromHex, SUI_CLOCK_OBJECT_ID, toHex } from "@mysten/sui/utils";
import {SealClient, SessionKey, getAllowlistedKeyServers } from "@mysten/seal";
import { useParams } from "react-router-dom";

const TTL_MIN = 1;
export interface FeedData {
  id: string;
  fee: string;
  ttl: string;
  owner: string;
  name: string;
  blobIds: string[];
  subscriptionId?: string;
}

const FeedsToSubscribe: React.FC<{ suiAddress: string }> = ({ suiAddress }) => {
  const suiClient = useSuiClient();
  const { id } = useParams();

  const client = new SealClient({
    suiClient,
    serverObjectIds: getAllowlistedKeyServers("testnet"),
  });
  const [feed, setFeed] = useState<FeedData>();
  const [decryptedFileUrls, setDecryptedFileUrls] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const packageId = useNetworkVariable("packageId");
  const currentAccount = useCurrentAccount();
  const [currentSessionKey, setCurrentSessionKey] = useState<SessionKey | null>(null);
  const [reloadKey, setReloadKey] = useState(0);
  const [isDialogOpen, setIsDialogOpen] = useState(false);

  const { mutate: signPersonalMessage } = useSignPersonalMessage();
  
  const { mutate: signAndExecute } = useSignAndExecuteTransaction({
    execute: async ({ bytes, signature }) =>
      await suiClient.executeTransactionBlock({
        transactionBlock: bytes,
        signature,
        options: {
          showRawEffects: true,
          showEffects: true,
        },
      }),
  });
  
  useEffect(() => {
    getFeed();
  }, [getFeed]);

  async function getFeed() {
    // get all encrypted objects for the given service id
    const encryptedObjects = await suiClient.getDynamicFields({
      parentId: id!,
    }).then((res) => res.data.map((obj) => obj.name.value as string));
    
    // get the current service object
    const service = await suiClient.getObject({
      id: id!,
      options: { showContent: true },
    });
    const service_fields = (service.data?.content as { fields: any })?.fields || {};

    // get all subscriptions for the given sui address
    const res = await suiClient.getOwnedObjects({
      owner: suiAddress,
      options: {
        showContent: true,
        showType: true,
      },
      filter: {
        StructType: `${packageId}::subscription::Subscription`,      },
    });

    // get the current timestamp
    const clock = await suiClient.getObject({
      id: "0x6",
      options: { showContent: true },
    });
    const fields = (clock.data?.content as { fields: any })?.fields || {};
    const current_ms = fields.timestamp_ms;

    // find an expired subscription for the given service if exists. 
    const valid_subscription = res.data
    .map((obj) => {
      const fields = (obj!.data!.content as { fields: any }).fields;
      const x = {
        id: fields?.id.id,
        created_at: parseInt(fields?.created_at),
        service_id: fields?.service_id,
      };
      return x;
    })
    .filter((item) => item.service_id === service_fields.id.id)
    .find((item) => {
      return item.created_at + parseInt(service_fields.ttl) > current_ms;
    });

    const feed = {
      ...service_fields,
      id: service_fields.id.id,
      blobIds: encryptedObjects,
      subscriptionId: valid_subscription?.id,
    } as FeedData;
    setFeed(feed);
  }

  /**
   * Construct a ptb for the given package id, module name, sui address, sui client and inner id. This corresponds to the 
   * `entry fun seal_approve` in `subscription.move`.
   * @param packageId - The package id.
   * @param moduleName - The module name.
   * @param suiAddress - The sui address.
   * @param suiClient - The sui client.
   * @param subscriptionId - The subscription id.
   * @param serviceId - The service id.
   * @returns The transaction data in bytes. 
   */
  async function constructTxBytes(packageId: Uint8Array, moduleName: string, suiAddress: string, suiClient: SuiClient, subscriptionId: string, serviceId: Uint8Array): Promise<Uint8Array> {
    const tx = new Transaction();
    tx.setSender(suiAddress);
    tx.moveCall({
      target: `${toHex(packageId)}::${moduleName}::seal_approve`,
      arguments: [
        tx.pure.vector("u8", serviceId),
        tx.object(subscriptionId),
        tx.object(toHex(serviceId)),
        tx.object(SUI_CLOCK_OBJECT_ID)
      ]
    });
    return await tx.build( { client: suiClient, onlyTransactionKind: true })
  }

  async function handleSubscribe(serviceId: string, fee: number) {
    const address = currentAccount?.address!;
    const tx = new Transaction();
    tx.setGasBudget(10000000);
    tx.setSender(address);
    const subscription = tx.moveCall({
      target: `${packageId}::subscription::subscribe`,
      arguments: [
        coinWithBalance({
          balance: BigInt(fee),
        }),
        tx.object(serviceId),
        tx.object(SUI_CLOCK_OBJECT_ID)
      ],
    });
    tx.moveCall({
      target: `${packageId}::subscription::transfer`,
      arguments: [
        tx.object(subscription),
        tx.pure.address(address),
      ]
    });

    signAndExecute(
      {
        transaction: tx,
      },
      {
        onSuccess: async (result) => {
          console.log("res", result);
          getFeed();
        },
      },
    );
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
    serviceId: string,
    fee: number,
    subscriptionId?: string,
  ) => {
    if (!subscriptionId) {
      return handleSubscribe(serviceId, fee);
    }

    const txBytes = await constructTxBytes(
      fromHex(packageId),
      "subscription",
      suiAddress,
      suiClient,
      subscriptionId,
      fromHex(serviceId),
    );

    if (currentSessionKey && !currentSessionKey.isExpired() && currentSessionKey.getAddress() === suiAddress) {
      handleDecryption(blobIds, currentSessionKey, txBytes);
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
      {feed === undefined ? (
        <p>No files found for this service.</p>
      ) : (
      <Card key={feed!.id}>
        <Heading size="3">Files for subscription service {feed!.name} (ID {feed!.id})</Heading>        
        <Flex direction="column" align="start" gap="2">
            {feed!.blobIds.length === 0 ? (
              <p>No feeds found.</p>
            ) : (
              <Dialog.Root open={isDialogOpen} onOpenChange={setIsDialogOpen}>
              <Dialog.Trigger>
                <Button onClick={() => onView(feed!.blobIds, feed!.id, Number(feed!.fee), feed!.subscriptionId)}>
                  {feed!.subscriptionId ? <div>Download And Decrypt All Files</div> : <div>Subscribe for {feed!.fee} MIST for {Math.floor(parseInt(feed!.ttl) / 60 / 1000)} minutes</div>}
                </Button>
              </Dialog.Trigger>
              {decryptedFileUrls.length > 0 && (
              <Dialog.Content maxWidth="450px" key={reloadKey}>
                <Dialog.Title>View all files for this service</Dialog.Title>
                  <Flex direction="column" gap="2">
                    {decryptedFileUrls.map((decryptedFileUrl, index) => (
                      <div key={index}>
                        <img
                          src={decryptedFileUrl}
                          alt={`Decrypted image ${index + 1}`}
                          />
                        </div>
                      ))}
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
      </Card>)}
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

export default FeedsToSubscribe;
