#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>

static struct nf_hook_ops nfho;         //struct holding set of hook function options
//function to be called by hook

unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    register struct tcphdr *tcph;
    register struct iphdr *iph;

	printk(KERN_ERR "HII I am the hook function\r\n");
    if(skb){
		iph = ip_hdr(skb);
	    if(iph->protocol == IPPROTO_TCP)
		{
			tcph = tcp_hdr(skb);
			printk(KERN_INFO "HII nf hook called with tcp protocol and dest port: %d\r\n", tcph->dest);
	        return NF_ACCEPT;
		}
	}
	return NF_ACCEPT; //this will accept the packet
}

//Called when module loaded using 'insmod'
static int __init nf_hook_init(void)
{
  int ret = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
    struct net *n;
#endif
  nfho.hook = hook_func;                       //function to call when conditions below met
  nfho.hooknum = NF_INET_PRE_ROUTING;            //called right after packet recieved, first hook in Netfilter
  nfho.pf = PF_INET;                           //IPV4 packets
  nfho.priority = NF_IP_PRI_FIRST;             //set to highest priority over all other hook functions
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
    for_each_net(n)
        ret += nf_register_net_hook(n, &nfho);
#else
    ret = nf_register_hook(&nfho);
#endif
	printk(KERN_ERR "HII I am the hook in my init\r\n");

	return 0;                                    //return 0 for success
}

//Called when module unloaded using 'rmmod'
static void __exit nf_hook_exit(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
    struct net *n;
    for_each_net(n)
        nf_unregister_net_hook(n, &nfho);
#else
    nf_unregister_hook(&nfho);
#endif
	printk(KERN_INFO "BYEBYE from hook\r\n");
}


module_init(nf_hook_init);
module_exit(nf_hook_exit);
MODULE_LICENSE("Dual BSD/GPL");
