#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/tcp.h>
#include <linux/mm.h>
#include <linux/err.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/route.h>
#include <linux/ip.h>
#include <linux/netfilter_ipv4.h>
#include <net/tcp.h>
#include <net/ip.h>
#include <net/route.h>
#include <net/net_namespace.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Girish Joshi");
MODULE_DESCRIPTION("A Netfilter demo.");

void register_all(void);
void unregister_all(void );

static unsigned int new_hook(void *prev,
		             struct sk_buff *skb,
			     const struct nf_hook_state *state){
	printk(KERN_INFO "Packet detected\n");
	return NF_ACCEPT;
}

static const struct nf_hook_ops new_hook_ops __read_mostly ={
		.hook =		new_hook,
		.pf =		NFPROTO_IPV4,
		.hooknum =	NF_INET_POST_ROUTING,
		.priority =	NF_IP_PRI_FIRST,
};


void register_all(){
    return nf_register_net_hook(&init_net, &new_hook_ops);
}

void unregister_all(){
    return nf_unregister_net_hook(&init_net, &new_hook_ops);
}

static int __init hello_init(void)
{
    printk(KERN_INFO "Hello world! From Girish Joshi.\n");
    register_all();
    return 0;    // Non-zero return means that the module couldn't be loaded.
}

static void __exit hello_cleanup(void)
{
    printk(KERN_INFO "Cleaning up module.\n");
    unregister_all();
}

module_init(hello_init);
module_exit(hello_cleanup);
