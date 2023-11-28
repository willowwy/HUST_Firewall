#include "define.h"
#include "hash.h"
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netlink.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/time.h>
#include <linux/types.h>
#include <linux/udp.h>
#include <linux/version.h>
#include <net/sock.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("wwy");

unsigned hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
unsigned hook_func_nat_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
unsigned hook_func_nat_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
void header_analyse(struct sk_buff *skb, struct iphdr *hdr, unsigned short *src_port, unsigned short *dst_port,
                    unsigned char *flags);
unsigned TCP_check(unsigned src_IP, unsigned short src_port, unsigned dst_IP, unsigned short dst_port,
                   unsigned char flags);
unsigned UDP_check(unsigned src_IP, unsigned short src_port, unsigned dst_IP, unsigned short dst_port);
unsigned ICMP_check(unsigned src_IP, unsigned dst_IP);
unsigned char match(unsigned char protocol, unsigned src_IP, unsigned short src_port, unsigned dst_IP,
                    unsigned short dst_port);
void message_switch(unsigned char *message);
void netlink_recv(struct sk_buff *skb);
void show_connection(void);
long get_time(void);

int pid;
unsigned firewall_outIP = 2408818880; // 网络字节序: 192.168.147.143
unsigned firewall_inIP = 2344659136;  // 网络字节序: 192.168.192.139
unsigned intra_net = 3232284801;      // 主机字节序: 192.168.192.129
unsigned net_mask = 0xffffff00;
unsigned char action = NF_DROP;
unsigned char rule_number = 0;
unsigned char nat_number = 0;
Rule rule_set[50];
NAT nat_set[50];
TCP_connection TCP_con[256];
UDP_connection UDP_con[256];
ICMP_connection ICMP_con[256];
static struct nf_hook_ops filter;
static struct nf_hook_ops nat_input;
static struct nf_hook_ops nat_output;
static struct sock *netlink_socket = NULL;
struct netlink_kernel_cfg netlink_cfg = {
    .groups = 0,
    .flags = 0,
    .input = netlink_recv,
    .cb_mutex = NULL,
    .bind = NULL,
    .unbind = NULL,
    .compare = NULL,
};

// --------------------------------------------------------------
// 模块初始化
static int firewall_init(void)
{
    filter.hook = (nf_hookfn *)hook_func;
    filter.pf = PF_INET;
    filter.hooknum = NF_INET_FORWARD;
    filter.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&filter);

    nat_input.hook = (nf_hookfn *)hook_func_nat_in; // 外网->内网
    nat_input.pf = PF_INET;
    nat_input.hooknum = NF_INET_PRE_ROUTING;
    nat_input.priority = NF_IP_PRI_NAT_DST;
    nf_register_hook(&nat_input);

    nat_output.hook = (nf_hookfn *)hook_func_nat_out; // 内网->外网
    nat_output.pf = PF_INET;
    nat_output.hooknum = NF_INET_POST_ROUTING;
    nat_output.priority = NF_IP_PRI_NAT_SRC;
    nf_register_hook(&nat_output);

    netlink_socket = netlink_kernel_create(&init_net, NETLINK, &netlink_cfg);
    if (!netlink_socket)
    {
        sock_release(netlink_socket->sk_socket);
        return -1;
    }

    return 0;
}

// 模块退出
static void firewall_exit(void)
{
    nf_unregister_hook(&filter);
    nf_unregister_hook(&nat_input);
    nf_unregister_hook(&nat_output);

    sock_release(netlink_socket->sk_socket);
}

module_init(firewall_init);
module_exit(firewall_exit);

// --------------------------------------------------------------
// hook
unsigned hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *hdr; // IP数据包头
    Log log;
    unsigned index;
    unsigned char TCP_flags;

    hdr = ip_hdr(skb);
    log.protocol = hdr->protocol;
    log.src_IP = hdr->saddr;
    log.dst_IP = hdr->daddr;
    header_analyse(skb, hdr, &log.src_port, &log.dst_port, &TCP_flags);

    switch (log.protocol)
    {
    case TCP: {
        index = TCP_check(log.src_IP, log.src_port, log.dst_IP, log.dst_port, TCP_flags);
        if (index == 256)
        {
            printk("myfirewall: [INFO] %ld TCP %u %u %u %u PASS\n", get_time(), log.src_IP, log.src_port, log.dst_IP,
                   log.dst_port);
            return NF_ACCEPT;
        }
        else if (index == 257)
        {
            printk("myfirewall: [WARN] %ld TCP %u %u %u %u CLASH\n", get_time(), log.src_IP, log.src_port, log.dst_IP,
                   log.dst_port);
            return NF_DROP;
        }
        else if (match(log.protocol, log.src_IP, log.src_port, log.dst_IP, log.dst_port) == 'Y')
        {
            TCP_con[index].src_IP = log.src_IP;
            TCP_con[index].src_port = log.src_port;
            TCP_con[index].dst_IP = log.dst_IP;
            TCP_con[index].dst_port = log.dst_port;
            TCP_con[index].flags = 1;
            printk("myfirewall: [INFO] %ld TCP %u %u %u %u PASS\n", get_time(), log.src_IP, log.src_port, log.dst_IP,
                   log.dst_port);
            return NF_ACCEPT;
        }
        else
        {
            printk("myfirewall: [WARN] %ld TCP %u %u %u %u ", get_time(), log.src_IP, log.src_port, log.dst_IP,
                   log.dst_port);
        }
        break;
    }

    case UDP: {
        index = UDP_check(log.src_IP, log.src_port, log.dst_IP, log.dst_port);
        if (index == 256)
        {
            printk("myfirewall: [INFO] %ld UDP %u %u %u %u PASS\n", get_time(), log.src_IP, log.src_port, log.dst_IP,
                   log.dst_port);
            return NF_ACCEPT;
        }
        else if (index == 257)
        {
            printk("myfirewall: [WARN] %ld UDP %u %u %u %u CLASH\n", get_time(), log.src_IP, log.src_port, log.dst_IP,
                   log.dst_port);
            return NF_DROP;
        }
        else if (match(log.protocol, log.src_IP, log.src_port, log.dst_IP, log.dst_port) == 'Y')
        {
            UDP_con[index].src_IP = log.src_IP;
            UDP_con[index].src_port = log.src_port;
            UDP_con[index].dst_IP = log.dst_IP;
            UDP_con[index].dst_port = log.dst_port;
            UDP_con[index].time = jiffies + 5 * HZ;
            printk("myfirewall: [INFO] %ld UDP %u %u %u %u PASS\n", get_time(), log.src_IP, log.src_port, log.dst_IP,
                   log.dst_port);
            return NF_ACCEPT;
        }
        else
        {
            printk("myfirewall: [WARN] %ld UDP %u %u %u %u ", get_time(), log.src_IP, log.src_port, log.dst_IP,
                   log.dst_port);
        }
        break;
    }

    case ICMP: {
        index = ICMP_check(log.src_IP, log.dst_IP);
        if (index == 256)
        {
            printk("myfirewall: [INFO] %ld ICMP %u %u PASS\n", get_time(), log.src_IP, log.dst_IP);
            return NF_ACCEPT;
        }
        else if (index == 257)
        {
            printk("myfirewall: [WARN] %ld ICMP %u %u CLASH\n", get_time(), log.src_IP, log.dst_IP);
            return NF_DROP;
        }
        else if (match(log.protocol, log.src_IP, log.src_port, log.dst_IP, log.dst_port) == 'Y')
        {
            ICMP_con[index].src_IP = log.src_IP;
            ICMP_con[index].dst_IP = log.dst_IP;
            ICMP_con[index].time = jiffies + 5 * HZ;
            printk("myfirewall: [INFO] %ld ICMP %u %u PASS\n", get_time(), log.src_IP, log.dst_IP);
            return NF_ACCEPT;
        }
        else
        {
            printk("myfirewall: [WARN] %ld ICMP %u %u ", get_time(), log.src_IP, log.dst_IP);
        }
    }
    }

    printk("DEFAULT-%s\n", action == NF_ACCEPT ? "PASS" : "DROP");
    return action;
}

// --------------------------------------------------------------
// hook(nat)
unsigned hook_func_nat_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    int i, tot_len, hdr_len;
    unsigned char flags;
    unsigned short src_port, dst_port;
    struct iphdr *hdr;
    struct tcphdr *tcph;
    struct udphdr *udph;

    hdr = ip_hdr(skb);
    header_analyse(skb, hdr, &src_port, &dst_port, &flags);

    for (i = 0; i < nat_number; ++i)
    {
        if (hdr->daddr == firewall_outIP && (!dst_port || (dst_port == nat_set[i].firewall_port)))
        {
            hdr->daddr = nat_set[i].intra_IP;
            hdr_len = 4 * hdr->ihl;
            tot_len = ntohs(hdr->tot_len);
            hdr->check = 0;
            hdr->check = ip_fast_csum(hdr, hdr->ihl);

            if (hdr->protocol == TCP)
            {
                tcph = (struct tcphdr *)(skb->data + (hdr->ihl * 4));
                tcph->dest = nat_set[i].intra_port;
                tcph->check = 0;
                skb->csum = csum_partial((unsigned char *)tcph, tot_len - hdr_len, 0);
                tcph->check = csum_tcpudp_magic(hdr->saddr, hdr->daddr, tot_len - hdr_len, hdr->protocol, skb->csum);
            }
            else if (hdr->protocol == UDP)
            {
                udph = (struct udphdr *)(skb->data + (hdr->ihl * 4));
                udph->dest = nat_set[i].intra_port;
                udph->check = 0;
                skb->csum = csum_partial((unsigned char *)udph, tot_len - hdr_len, 0);
                udph->check = csum_tcpudp_magic(hdr->saddr, hdr->daddr, tot_len - hdr_len, hdr->protocol, skb->csum);
            }

            return NF_ACCEPT;
        }
    }

    return NF_ACCEPT;
}

unsigned hook_func_nat_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    int i, tot_len, hdr_len;
    unsigned char flags;
    unsigned short src_port, dst_port;
    struct iphdr *hdr;
    struct tcphdr *tcph;
    struct udphdr *udph;

    hdr = ip_hdr(skb);
    header_analyse(skb, hdr, &src_port, &dst_port, &flags);

AGAIN:
    for (i = 0; i < nat_number; ++i)
    {
        if (hdr->saddr == nat_set[i].intra_IP && (!src_port || (src_port == nat_set[i].intra_port)))
        {
            hdr->saddr = firewall_outIP;
            hdr_len = 4 * hdr->ihl;
            tot_len = ntohs(hdr->tot_len);
            hdr->check = 0;
            hdr->check = ip_fast_csum(hdr, hdr->ihl);

            if (hdr->protocol == TCP)
            {
                tcph = (struct tcphdr *)(skb->data + (hdr->ihl * 4));
                tcph->source = nat_set[i].intra_port;
                tcph->check = 0;
                skb->csum = csum_partial((unsigned char *)tcph, tot_len - hdr_len, 0);
                tcph->check = csum_tcpudp_magic(hdr->saddr, hdr->daddr, tot_len - hdr_len, hdr->protocol, skb->csum);
            }
            else if (hdr->protocol == UDP)
            {
                udph = (struct udphdr *)(skb->data + (hdr->ihl * 4));
                udph->source = nat_set[i].intra_port;
                udph->check = 0;
                skb->csum = csum_partial((unsigned char *)udph, tot_len - hdr_len, 0);
                udph->check = csum_tcpudp_magic(hdr->saddr, hdr->daddr, tot_len - hdr_len, hdr->protocol, skb->csum);
            }

            return NF_ACCEPT;
        }
    }

    if ((ntohl(hdr->saddr) & net_mask) == intra_net && (ntohl(hdr->daddr) & net_mask) != intra_net &&
        hdr->saddr != firewall_outIP)
    {
        nat_set[nat_number].intra_IP = hdr->saddr;
        nat_set[nat_number].intra_port = src_port;
        nat_set[nat_number].firewall_port = src_port;
        nat_set[nat_number].number = nat_number + 1;
        ++nat_number;
        goto AGAIN;
    }
    return NF_ACCEPT;
}

// --------------------------------------------------------------
// netlink
void netlink_recv(struct sk_buff *skb)
{
    struct nlmsghdr *nlh = NULL;
    unsigned char message[MAX_MSG_LEN];

    nlh = nlmsg_hdr(skb);
    if ((nlh->nlmsg_len < NLMSG_HDRLEN) || (skb->len < nlh->nlmsg_len))
    {
        return;
    }
    pid = nlh->nlmsg_pid;

    memcpy(message, NLMSG_DATA(nlh), MAX_MSG_LEN);
    message_switch(message);
}

static void netlink_send(unsigned char *message, int len)
{
    struct sk_buff *skb;
    struct nlmsghdr *nlh;

    skb = alloc_skb(NLMSG_SPACE(len), GFP_KERNEL);
    nlh = nlmsg_put(skb, 0, 0, 0, len, 0);
    NETLINK_CB(skb).portid = 0;
    NETLINK_CB(skb).dst_group = 0;
    memcpy(NLMSG_DATA(nlh), message, len);
    netlink_unicast(netlink_socket, skb, pid, MSG_DONTWAIT);
}

// --------------------------------------------------------------
// 其他功能
void message_switch(unsigned char *message)
{
    Rule rule;
    NAT nat;
    int i;
    unsigned char rm_num;

    switch (*message)
    {
    case '0': // add rule
    {
        memcpy(&rule, &message[1], sizeof(Rule));
        rule_set[rule_number++] = rule;
        break;
    }
    case '1': // mod rule
    {
        memcpy(&rule, &message[1], sizeof(Rule));
        rule_set[rule.number - 1] = rule;
        break;
    }
    case '2': // del rule
    {
        rm_num = message[1];
        memcpy(rule_set + rm_num - 1, rule_set + rm_num, (rule_number-- - rm_num) * sizeof(Rule));
        for (i = rm_num - 1; i < rule_number; ++i)
        {
            rule_set[i].number = i + 1;
        }
        break;
    }
    case '3': // ls connection
    {
        show_connection();
        break;
    }
    case '4': // add nat
    {
        memcpy(&nat, &message[1], sizeof(NAT));
        nat_set[nat_number++] = nat;
        break;
    }
    case '5': // del nat
    {
        rm_num = message[1];
        memcpy(nat_set + rm_num - 1, nat_set + rm_num, (nat_number-- - rm_num) * sizeof(NAT));
        for (i = rm_num - 1; i < nat_number; ++i)
        {
            nat_set[i].number = i + 1;
        }
        break;
    }
    case '6': // mod action
    {
        action = message[1];
    }
    }
}

void show_connection(void)
{
    int i;
    Rule connection;

    for (i = 0; i < 256; ++i)
    {
        if (TCP_con[i].flags)
        {
            connection.protocol = TCP;
            connection.src_IP = TCP_con[i].src_IP;
            connection.dst_IP = TCP_con[i].dst_IP;
            connection.src_port = TCP_con[i].src_port;
            connection.dst_port = TCP_con[i].dst_port;
            netlink_send((unsigned char*)&connection, sizeof(Rule));
        }
        if (jiffies < UDP_con[i].time)
        {
            connection.protocol = UDP;
            connection.src_IP = UDP_con[i].src_IP;
            connection.dst_IP = UDP_con[i].dst_IP;
            connection.src_port = UDP_con[i].src_port;
            connection.dst_port = UDP_con[i].dst_port;
            netlink_send((unsigned char*)&connection, sizeof(Rule));
        }
        if (jiffies < ICMP_con[i].time)
        {
            connection.protocol = ICMP;
            connection.src_IP = ICMP_con[i].src_IP;
            connection.dst_IP = ICMP_con[i].dst_IP;
            connection.src_port = 0;
            connection.dst_port = 0;
            netlink_send((unsigned char*)&connection, sizeof(Rule));
        }
    }

    connection.action = 'q';
    netlink_send((unsigned char*)&connection, sizeof(Rule));
}

long get_time(void)
{
    struct timeval time;
    do_gettimeofday(&time);
    return time.tv_sec;
}

// --------------------------------------------------------------
// 规则比对
void header_analyse(struct sk_buff *skb, struct iphdr *hdr, unsigned short *src_port, unsigned short *dst_port,
                    unsigned char *flags)
{
    struct tcphdr *tcp;
    struct udphdr *udp;
    *src_port = 0;
    *dst_port = 0;
    if (hdr->protocol == TCP)
    {
        tcp = (struct tcphdr *)(skb->data + 4 * hdr->ihl); // skb->data: 网络数据包中IP数据包的起点地址
        *src_port = tcp->source;
        *dst_port = tcp->dest;
        *flags = (tcp->ack << 4) ^ (tcp->rst << 2) ^ tcp->syn << 1 ^ tcp->fin;
    }
    else if (hdr->protocol == UDP)
    {
        udp = (struct udphdr *)(skb->data + 4 * hdr->ihl); // hdr->ihl: IP数据包的首部长度，以4字节为单位
        *src_port = udp->source;
        *dst_port = udp->dest;
    }
}

unsigned TCP_check(unsigned src_IP, unsigned short src_port, unsigned dst_IP, unsigned short dst_port,
                   unsigned char flags)
{
    unsigned char index;
    unsigned char FIN, SYN, RST, ACK;
    index = (my_hash_32(src_IP) ^ my_hash_32(dst_IP) ^ my_hash_16(src_port) ^ my_hash_16(dst_port)) % 256;

    FIN = flags & 1;
    SYN = flags & 1 << 1;
    RST = flags & 1 << 2;
    ACK = flags & 1 << 4;

    // 测试时使用，为保证已存在的连接不断
    if (TCP_con[index].flags == 0 && !SYN && ACK)
    {
        return 256;
    }

    if (TCP_con[index].flags) // 已有连接
    {
        if ((src_IP == TCP_con[index].src_IP && src_port == TCP_con[index].src_port &&
             dst_IP == TCP_con[index].dst_IP && dst_port == TCP_con[index].dst_port) ||
            (src_IP == TCP_con[index].dst_IP && src_port == TCP_con[index].dst_port &&
             dst_IP == TCP_con[index].src_IP && dst_port == TCP_con[index].src_port))
        {
            if (RST || TCP_con[index].flags == 3) // RST或第4次挥手
            {
                TCP_con[index].flags = 0;
            }
            else if (FIN)
            {
                ++TCP_con[index].flags;
            }
            return 256;
        }
        else // 表示发生碰撞，丢弃
        {
            return 257;
        }
    }
    else if (SYN && !ACK) // 第一次握手
    {
        return index;
    }
}

unsigned UDP_check(unsigned src_IP, unsigned short src_port, unsigned dst_IP, unsigned short dst_port)
{
    unsigned char index;
    index = (my_hash_32(src_IP) ^ my_hash_32(dst_IP) ^ my_hash_16(src_port) ^ my_hash_16(dst_port)) % 256;

    if (jiffies < UDP_con[index].time)
    {
        if ((src_IP == UDP_con[index].src_IP && src_port == UDP_con[index].src_port &&
             dst_IP == UDP_con[index].dst_IP && dst_port == UDP_con[index].dst_port) ||
            (src_IP == UDP_con[index].dst_IP && src_port == UDP_con[index].dst_port &&
             dst_IP == UDP_con[index].src_IP && dst_port == UDP_con[index].src_port))
        {
            UDP_con[index].time = jiffies + 10 * HZ; // 更新超时时间
            return 256;                              // 表示连接存在且未超时
        }
        else
        {
            return 257; // 表示发生碰撞，丢弃
        }
    }
    else
    {
        return index; // 表示旧连接超时，需建立新连接
    }
}

unsigned ICMP_check(unsigned src_IP, unsigned dst_IP)
{
    unsigned char index;
    index = (my_hash_32(src_IP) ^ my_hash_32(dst_IP)) % 256;

    if (jiffies < ICMP_con[index].time)
    {
        if ((src_IP == ICMP_con[index].src_IP && dst_IP == ICMP_con[index].dst_IP) ||
            (src_IP == ICMP_con[index].dst_IP && dst_IP == ICMP_con[index].src_IP))
        {
            ICMP_con[index].time = jiffies + 10 * HZ; // 更新超时时间
            return 256;                               // 表示连接存在且未超时
        }
        else
        {
            return 257; // 表示发生碰撞，丢弃
        }
    }
    else
    {
        return index; // 表示旧连接超时，需建立新连接
    }
}

unsigned char match(unsigned char protocol, unsigned src_IP, unsigned short src_port, unsigned dst_IP,
                    unsigned short dst_port)
{
    int i;
    for (i = 0; i < rule_number; ++i)
    {
        if (rule_set[i].protocol != protocol && rule_set[i].protocol != ANY)
        {
            continue;
        }
        if (rule_set[i].src_IP != src_IP && rule_set[i].src_IP != ANY)
        {
            continue;
        }
        if (rule_set[i].dst_IP != dst_IP && rule_set[i].dst_IP != ANY)
        {
            continue;
        }
        if (protocol == TCP || protocol == UDP)
        {
            if (rule_set[i].src_port != src_port && rule_set[i].src_port != ANY)
            {
                continue;
            }

            if (rule_set[i].dst_port != dst_port && rule_set[i].dst_port != ANY)
            {
                continue;
            }
        }
        return rule_set[i].action;
    }

    return 'N';
}
