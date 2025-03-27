// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { useCurrentAccount, useSuiClient } from "@mysten/dapp-kit";
import { useEffect, useState } from "react";
import { useNetworkVariable } from "./networkConfig";
import { Button, Card } from "@radix-ui/themes";

export interface Cap {
    id: string;
    service_id: string;
}

export interface CardItem {
    id: string;
    fee: string;
    ttl: string;
    name: string;
    owner: string;
}
  
export function AllServices() {
    const packageId = useNetworkVariable("packageId");
    const currentAccount = useCurrentAccount();
    const suiClient = useSuiClient();

    const [cardItems, setCardItems] = useState<CardItem[]>([]);
    
    useEffect(() => {
      getCapObj();
    }, [getCapObj]);
    
    async function getCapObj() {
      // get all owned cap objects
      const res = await suiClient.getOwnedObjects({
        owner: currentAccount?.address!,
        options: {
          showContent: true,
          showType: true,
        },
        filter: {
          StructType: `${packageId}::subscription::Cap`,
        },
      });
      const caps = res.data
        .map((obj) => {
          const fields = (obj!.data!.content as { fields: any }).fields;
          return {
            id: fields?.id.id,
            service_id: fields?.service_id,
          };
        })
      .filter((item) => item !== null) as Cap[];

      // get all services of all the owned cap objects
      const cardItems: CardItem[] = await Promise.all(
      caps.map(async (cap) => {
        const service = await suiClient.getObject({
          id: cap.service_id,
          options: { showContent: true },
        });
        const fields =
          (service.data?.content as { fields: any })?.fields || {};
        return {
          id: cap.service_id,
          fee: fields.fee,
          ttl: fields.ttl,
          owner: fields.owner,
          name: fields.name,
        };
      }),
    );
    setCardItems(cardItems);
    }
    
    return (
      <div>
        <h3>Admin View: All Subscription Services</h3>
        <p>This is all the services that you have created. Click manage to upload new files to the service.</p>
        {cardItems.map((item) => (
          <Card key={`${item.id}`}>
            <p><strong>{item.name}</strong></p>
            <p>Subscription Fee: {item.fee} MIST</p>
            <p>Subscription Duration: {item.ttl ? parseInt(item.ttl) / 60 / 1000 : 'null'} minutes</p>
            <Button 
            onClick={() => {
              window.open(`${window.location.origin}/subscription-example/admin/service/${item.id}`, '_blank');
            }}
            >Manage
            </Button>
          </Card>)
        )}
      </div>
    )
}
