#define ANY 0
#define ICMP 1
#define TCP 6
#define UDP 17
#define NETLINK 30
#define MAX_MSG_LEN 20

typedef struct
{
    unsigned char action;    // 动作：拒绝/放行
    unsigned char protocol;  // 协议：ICMP/TCP/UDP
    unsigned char number;    // 规则的编号
    unsigned short src_port; // 源端口
    unsigned short dst_port; // 目的端口
    unsigned src_IP;         // 源IP
    unsigned dst_IP;         // 目的IP
} Rule;

typedef struct
{
    unsigned char number;
    unsigned short firewall_port;
    unsigned short intra_port;
    unsigned intra_IP;
    
} NAT;

typedef struct Log
{
    unsigned char action;    // 动作：拒绝/放行
    unsigned char protocol;  // 协议：ICMP/TCP/UDP
    unsigned short src_port; // 源端口
    unsigned short dst_port; // 目的端口
    unsigned src_IP;         // 源IP
    unsigned dst_IP;         // 目的IP
    long time;
    struct Log *next;
} Log;
