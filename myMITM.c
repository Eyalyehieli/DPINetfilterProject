#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/inet.h>/


//TODO:infect the packet
MODULE_LICENSE("Dual BSD/GPL");
static dev_t my_dev = 0;
static struct cdev *my_cdev = NULL;
static struct nf_hook_ops nfho;         //struct holding set of hook function options
//function to be called by hook

unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct udphdr *udph;
    struct iphdr *iph;
    //unsigned char* dest_port="\x50\x50";
    //unsigned char* dest_ip="\x7f\x00\x00\x01";
    unsigned char* payload;
    int i=0;

    //printk(KERN_ALERT "myMITM inside hook function\n");
    if(skb)
    {
		//printk(KERN_ALERT "myMITM inside hook function after idntify UDP\n");
		iph = (struct iphdr *)skb_network_header(skb);
		if(iph->protocol==IPPROTO_UDP)
	    {
           printk(KERN_ALERT "myMITM inside hook function after idntify UDP\n");
           udph=(struct udphdr*)skb_transport_header(skb);
           printk("myMITM udph->dest = %d\n",udph->dest);
           //printk("myMITM udph->source = %d\n",udph->source);
           printk("myMITM iph->saddr = %x\n",iph->saddr);
           //printk("myMITM iph->daddr = %x\n",iph->daddr);

           //printk("dest_port = %x\n",udph->dest);
           //printk("udph->dest = %x\n",udph->dest);
           if(((udph->dest) == htons(8080))&&(iph->saddr == in_aton("127.0.0.1")))
           {
              payload=skb->data+(iph->ihl * 4)+sizeof(udph);

			  //printk("myMITM  skb->tail %p\n",skb->tail);
			  for (i=0;i<9;i++)
			     printk("payload[%d]=%x \n",i,payload[i]);
              // change UDP data
              for (i=0;i<9;i++)
              {
			     payload[i]=payload[i] + 1 ;
              }
              printk("myMITM change payload\n");
              for (i=0;i<9;i++)
			     printk("payload[%d]=%x \n",i,payload[i]);

           }

	    }
	}
	return NF_ACCEPT; //this will accept the packet
}

//Called when module loaded using 'insmod'
static int __init nf_hook_init(void)
{
  int ret = 0;
  int res=0;
  res = alloc_chrdev_region(&my_dev, 0, 1, "myMITM");
  if (res < 0)
    goto register_failed;

  printk(KERN_ALERT "myMITM registered\n");
  my_cdev = cdev_alloc();
  if (NULL == my_cdev)
  {
    res = -ENOMEM;
    goto cdev_fail;
  }
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
	printk(KERN_ALERT "HII I am the hook in my init MITM\r\n");
	return 0;
    cdev_fail:
    printk(KERN_ALERT "mtyMITM registration failed... unregistering\n");
    unregister_chrdev_region(my_dev, 1);
    register_failed:
    return res;
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
