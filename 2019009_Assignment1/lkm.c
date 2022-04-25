#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

static struct nf_hook_ops *nfho=NULL;

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Agamdeep Bains");
MODULE_DESCRIPTION("A simple linux netfilter kernel module");
MODULE_VERSION("1.00");

static unsigned int hook_func(void *priv,struct sk_buff *skb,const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	if (!skb) {
		return NF_ACCEPT;
    }
	iph=ip_hdr(skb);
	if(iph->protocol==IPPROTO_UDP) {
		return NF_ACCEPT;
	}
	if(iph->protocol==IPPROTO_TCP)
		tcph=tcp_hdr(skb);
        if(tcph->syn==0 && tcph->ack==0 && tcph->urg==0 && tcph->rst==0 && tcph->fin==0 && tcph->psh==0) {
            printk(KERN_INFO "Dropped null scan packets\n");
            return NF_DROP;
        }
        if(tcph->syn==0 && tcph->ack==1 && tcph->urg==0 && tcph->rst==0 && tcph->fin==0 && tcph->psh==0) {
            printk(KERN_INFO "Dropped ack scan packets\n");
            return NF_DROP;
        }
        if(tcph->syn==0 && tcph->ack==0 && tcph->urg==0 && tcph->rst==0 && tcph->fin==1 && tcph->psh==0) {
            printk(KERN_INFO "Dropped fin scan packets\n");
            return NF_DROP;
        }
        if(tcph->syn==0 && tcph->ack==0 && tcph->urg==1 && tcph->rst==0 && tcph->fin==1 && tcph->psh==1) {
            printk(KERN_INFO "Dropped xmas scan packets (not a merry christmas for someone)\n");
            return NF_DROP;
        }
	}
    if(iph->protocol==IPPROTO_ICMP) {
        printk(KERN_INFO "Dropped ICMP packets\n");
        return NF_DROP;
    }
	return NF_ACCEPT;
}

static int __init lkm_init(void) {
	nfho=(struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	nfho->hook=hook_func;
	nfho->hooknum=NF_INET_PRE_ROUTING;
	nfho->pf=PF_INET;
	nfho->priority=NF_IP_PRI_FIRST;
	nf_register_net_hook(&init_net,nfho);
}

static void __exit lkm_exit(void)
{
	nf_unregister_net_hook(&init_net,nfho);
	kfree(nfho);
}

module_init(lkm_init);
module_exit(lkm_exit);
