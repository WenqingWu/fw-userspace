#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
//#include <stddef.h>
//#include <sys/socket.h>

#include "include/linux/netdevice.h"
#include "include/linux/skbuff.h"
#include "include/linux/netfilter.h"
#include "include/linux/netfilter_ipv4.h"


/*
 * sample okfn called in NF_HOOK
 */
int okfn_sample(struct sk_buff *skb)
{
    /* processing */
    printf("-------------this is okfn.----------\n");
    return 1;
}

int main()
{
    struct sk_buff skbuff_tmp = {0, 0};
    struct sk_buff *skbuff = &skbuff_tmp;
    struct net_device *dev1;
    struct net_device *dev2;
    int ret;
    
//    memcpy(skbuff, packet, sizeof(struct sk_buff));

    /*call NF_IP_PRE_ROUTING, just like done in ip_input.c*/
    ret = NF_HOOK(PF_INET, NF_IP_PRE_ROUTING, skbuff, NULL, NULL,
		       okfn_sample);

#if 0
    /*call NF_IP_LOCAL_IN, just like done in ip_input.c*/
    ret = NF_HOOK(PF_INET, NF_IP_LOCAL_IN, skbuff, skbuff->dev, NULL,
		       okfn_sample);


    /*call NF_IP_FORWARD, just like done in ip_forward.c*/
    ret = NF_HOOK(PF_INET, NF_IP_FORWARD, skbuff, skbuff->dev, dev2,
		       okfn_sample);


    /*call NF_IP_LOCAL_OUT, just like done in ip_output.c*/
    ret = NF_HOOK(PF_INET, NF_IP_LOCAL_OUT, skbuff, NULL, dev2
		       okfn_sample);


    /*call NF_IP_POST_ROUTING, just like done in ip_output.c*/
    ret = NF_HOOK(PF_INET, NF_IP_POST_ROUTING, skbuff, NULL, dev2,
		       okfn_sample);

#endif

    return 0;
}


