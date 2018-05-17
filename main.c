#include <stdio.h>
#include <stdlib.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/snmp.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/arp.h>
#include <net/icmp.h>

/*
 * sample okfn called in NF_HOOK
 */
int okfn_sample(struct sk_buff *skb)
{
    /* processing */
    printf("-------------this is okfn.----------\n")
    return 1;
}

int main()
{
    struct sk_buff *skb = (struct sk_buff *)malloc(sizeof(struct sk_buff));
//    struct net_device *dev1;
//   struct net_device *dev2;
    int ret;
    char *packet = "0x6a8d01e7080045003e234500008011"
    
    memcpy(skb, packet, sizeof(struct sk_buff));

    /*call NF_IP_PRE_ROUTING, just like done in ip_input.c*/
    ret = NF_HOOK(PF_INET, NF_IP_PRE_ROUTING, skb, NULL, NULL,
		       okfn_sample);

#if 0
    /*call NF_IP_LOCAL_IN, just like done in ip_input.c*/
    ret = NF_HOOK(PF_INET, NF_IP_LOCAL_IN, skb, skb->dev, NULL,
		       okfn_sample);


    /*call NF_IP_FORWARD, just like done in ip_forward.c*/
    ret = NF_HOOK(PF_INET, NF_IP_FORWARD, skb, skb->dev, dev2,
		       okfn_sample);


    /*call NF_IP_LOCAL_OUT, just like done in ip_output.c*/
    ret = NF_HOOK(PF_INET, NF_IP_LOCAL_OUT, skb, NULL, dev2
		       okfn_sample);


    /*call NF_IP_POST_ROUTING, just like done in ip_output.c*/
    ret = NF_HOOK(PF_INET, NF_IP_POST_ROUTING, skb, NULL, dev2,
		       okfn_sample);

#endif

    return 0;
}


