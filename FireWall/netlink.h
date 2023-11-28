#include <linux/netlink.h>
#include <linux/socket.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "define.h"

typedef struct
{
    struct nlmsghdr hdr;
    char msg[MAX_MSG_LEN];
} Message;

int netlinkCreateSocket(void)
{
    // 创建netlink套接字
    return socket(AF_NETLINK, SOCK_RAW, NETLINK);
}

int netlink_bind(int socket_fd)
{
    // 设置本地地址
    struct sockaddr_nl local;
    memset(&local, 0, sizeof(local));
    local.nl_family = AF_NETLINK;
    local.nl_pid = getpid();
    local.nl_groups = 0;

    // 绑定netlink套接字和本地地址
    return bind(socket_fd, (struct sockaddr *)&local, sizeof(local));
}

int netlink_send(int socket_fd, unsigned char *message, unsigned messageLen)
{
    // 创建消息头
    struct nlmsghdr *nlh;
    nlh = (struct nlmsghdr *)malloc(sizeof(Message));
    if (nlh == NULL)
    {
        // malloc失败
        return -1;
    }

    memset(nlh, 0, sizeof(struct nlmsghdr)); // 填充消息
    nlh->nlmsg_len = NLMSG_SPACE(messageLen + 1);
    nlh->nlmsg_flags = 0;
    nlh->nlmsg_type = 0;
    nlh->nlmsg_seq = 0;
    nlh->nlmsg_pid = getpid();
    memcpy(NLMSG_DATA(nlh), message, messageLen);

    // 设置内核地址
    struct sockaddr_nl kernel;
    memset(&kernel, 0, sizeof(kernel));
    kernel.nl_family = AF_NETLINK;
    kernel.nl_pid = 0; // 发往内核
    kernel.nl_groups = 0;

    int ret;
    ret = sendto(socket_fd, nlh, nlh->nlmsg_len, 0, (struct sockaddr *)&kernel, sizeof(kernel));
    if (!ret) // send失败
    {
        return -2;
    }

    return 0;
}

int netlink_recv(int socket_fd, Message *message, int len)
{
    // 设置内核地址
    struct sockaddr_nl kernel;
    memset(&kernel, 0, sizeof(kernel));
    kernel.nl_family = AF_NETLINK;
    kernel.nl_pid = 0; // 发往内核
    kernel.nl_groups = 0;

    int ret;
    unsigned kernelLen = sizeof(kernel);
    ret = recvfrom(socket_fd, message, len, 0, (struct sockaddr *)&kernel, &kernelLen);
    if (!ret) // recv失败
    {
        return -1;
    }

    return 0;
}