#include "netlink.h"
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <linux/ip.h>
#include <list>
#include <map>
#include <string>
#include <utility>
using namespace std;

void input_rule(Rule &rule);
void input_nat(NAT &nat);
void input_IP(unsigned &IP);
void input_port(unsigned short &port);
string IP_transform(unsigned IP);
string port_transform(unsigned short port);
string find_protocol(unsigned char protocol);
map<string, unsigned char> protocol_map;

int main()
{
    system("sudo insmod firewall.ko");
    system("sudo sysctl -w net.ipv4.ip_forward=1");
    system("python log.py &");

    time_t time_ptr;
    struct tm *tmp_ptr = NULL;

    int socket_fd = netlinkCreateSocket(); // 创建netlink套接字
    int ret = netlink_bind(socket_fd);     // 绑定netlink套接字和本地地址

    Rule rule, rule_set[50];
    NAT nat, nat_set[50];
    unsigned char rule_number = 0; // 当前规则的数量
    unsigned char nat_number = 0;  // 当前nat的数量
    protocol_map.insert(make_pair("TCP", TCP));
    protocol_map.insert(make_pair("UDP", UDP));
    protocol_map.insert(make_pair("ICMP", ICMP));

    bool flag = true;
    while (flag)
    {
        cout << "——————————————————————————————————————————————————————————————————————\n"
             << "请按照规则输入指令进行相应的防火墙控制，使用方式如下：\n"
             << "1. 添加防火墙规则   ||add-rule ||protocol ||src_IP   ||src_port ||dst_IP   ||dst_port ||action\n"
             << "2. 修改防火墙规则   ||mod-rule ||number   ||protocol ||src_IP   ||src_port ||dst_IP   ||dst_port ||action\n"
             << "3. 删除防火墙规则   ||del-rule ||number\n"
             << "4. 展示防火墙规则   ||ls-rule\n"
             << "5. 展示已有连接     ||ls-connection\n"
             << "6. 保存防火墙规则   ||save ||path\n"
             << "7. 载入防火墙规则   ||load ||path\n"
             << "8. 添加NAT规则      ||add-nat ||intra_IP ||intra_port ||firewall_port\n"
             << "9. 删除NAT规则      ||del-nat ||number\n"
             << "10.展示NAT规则      ||ls-nat\n"
             << "11.设置默认动作     ||action ||Y/N\n"
             << "退出程序            q\n"
             << "——————————————————————————————————————————————————————————————————————\n"
             << "请输入指令：\n";
        string command;
        getline(cin, command);
        char temp[100];
        strcpy(temp, command.c_str());
        command = strtok(temp, " ");

        if (command == "add-rule") // 0
        {
            input_rule(rule);
            rule.number = rule_number + 1;
            rule_set[rule_number++] = rule;

            unsigned char message[MAX_MSG_LEN] = "0";
            memcpy(&message[1], (unsigned char *)&rule, sizeof(Rule));
            int ret = netlink_send(socket_fd, message, sizeof(Rule) + 1);
        }
        else if (command == "mod-rule") // 1
        {
            unsigned char mod_num = atoi(strtok(NULL, " "));
            if (mod_num > rule_number)
            {
                cout << "[ERROR] 规则不存在\n";
                continue;
            }

            input_rule(rule);
            rule.number = mod_num;
            rule_set[rule.number - 1] = rule;

            unsigned char message[MAX_MSG_LEN] = "1";
            memcpy(&message[1], (unsigned char *)&rule, sizeof(Rule));
            int ret = netlink_send(socket_fd, message, sizeof(Rule) + 1);
        }
        else if (command == "del-rule") // 2
        {
            unsigned char rm_num = atoi(strtok(NULL, " "));
            if (rm_num > rule_number)
            {
                cout << "[ERROR] 规则不存在\n";
                continue;
            }

            // 前移其他规则
            memcpy(rule_set + rm_num - 1, rule_set + rm_num, (rule_number-- - rm_num) * sizeof(Rule));
            for (int i = rm_num - 1; i < rule_number; ++i)
            {
                rule_set[i].number = i + 1;
            }

            unsigned char message[3] = "2";
            message[1] = rm_num;
            int ret = netlink_send(socket_fd, message, 2);
        }
        else if (command == "ls-rule")
        {
            cout << "————————————————————————————————————————————————————————————————————————\n";
            cout << "|编号| 协议 |       源IP      | 源端口 |      目的IP     |目的端口|策略|\n";
            for (int i = 0; i < rule_number; ++i)
            {
                cout << "————————————————————————————————————————————————————————————————————————\n";
                cout << "| " << setw(2) << (unsigned)rule_set[i].number << " | " << setw(4)
                     << find_protocol(rule_set[i].protocol) << " | " << setw(15) << IP_transform(rule_set[i].src_IP)
                     << " | " << setw(6) << port_transform(rule_set[i].src_port) << " | " << setw(15)
                     << IP_transform(rule_set[i].dst_IP) << " | " << setw(6) << port_transform(rule_set[i].dst_port)
                     << " |  " << rule_set[i].action << " |" << endl;
            }
            cout << "————————————————————————————————————————————————————————————————————————\n";
        }
        else if (command == "ls-connection") // 3
        {
            unsigned char send_message = '3';
            int ret = netlink_send(socket_fd, &send_message, 2);

            cout << "——————————————————————————————————————————————————————————————\n";
            cout << "| 协议 |       源IP      | 源端口 |      目的IP     |目的端口|\n";
            cout << "——————————————————————————————————————————————————————————————\n";

            Rule connection;
            Message recv_message;
            while (!netlink_recv(socket_fd, &recv_message, sizeof(Message)))
            {
                memcpy(&connection, &recv_message.msg, sizeof(connection));
                if (connection.action == 'q')
                {
                    break;
                }
                cout << "| " << setw(4) << find_protocol(connection.protocol) << " | " << setw(15)
                     << IP_transform(connection.src_IP) << " | " << setw(6) << port_transform(connection.src_port)
                     << " | " << setw(15) << IP_transform(connection.dst_IP) << " | " << setw(6)
                     << port_transform(connection.dst_port) << " | " << endl;
                cout << "——————————————————————————————————————————————————————————————\n";
            }
        }
        else if (command == "save")
        {
            string path = strtok(NULL, " ");
            ofstream file(path, ios::trunc);
            for (int i = 0; i < rule_number; ++i)
            {
                file << find_protocol(rule_set[i].protocol) << ' ' << IP_transform(rule_set[i].src_IP) << ' '
                     << port_transform(rule_set[i].src_port) << ' ' << IP_transform(rule_set[i].dst_IP) << ' '
                     << port_transform(rule_set[i].dst_port) << ' ' << rule_set[i].action << endl;
            }
            file.close();
        }
        else if (command == "load")
        {
            string path = strtok(NULL, " ");
            ifstream file(path, ios::in);
            string line;
            while (getline(file, line))
            {
                char temp[100];
                strcpy(temp, line.c_str());
                strtok(temp, " ");
                input_rule(rule);
                rule.number = rule_number + 1;
                rule_set[rule_number++] = rule;
                unsigned char message[MAX_MSG_LEN] = "0";
                memcpy(&message[1], (unsigned char *)&rule, sizeof(Rule));
                int ret = netlink_send(socket_fd, message, sizeof(Rule) + 1);
            }
            file.close();
        }
        else if (command == "add-nat") // 4
        {
            input_nat(nat);
            nat.number = nat_number + 1;
            nat_set[nat_number++] = nat;

            unsigned char message[MAX_MSG_LEN] = "4";
            memcpy(&message[1], (unsigned char *)&nat, sizeof(NAT));
            int ret = netlink_send(socket_fd, message, sizeof(NAT) + 1);
        }
        else if (command == "del-nat") // 5
        {
            unsigned char rm_num = atoi(strtok(NULL, " "));
            if (rm_num > rule_number)
            {
                cout << "[ERROR] 规则不存在\n";
                continue;
            }

            // 前移其他规则
            memcpy(nat_set + rm_num - 1, nat_set + rm_num, (nat_number-- - rm_num) * sizeof(NAT));
            for (int i = rm_num - 1; i < nat_number; ++i)
            {
                nat_set[i].number = i + 1;
            }

            unsigned char message[3] = "5";
            message[1] = rm_num;
            int ret = netlink_send(socket_fd, message, 2);
        }
        else if (command == "ls-nat")
        {
            cout << "————————————————————————————————————————————————————————————————————————\n";
            cout << "|编号|       内网IP      |内网端口|防火墙端口|\n";
            for (int i = 0; i < nat_number; ++i)
            {
                cout << "——————————————————————————————————————————————\n";
                cout << "| " << setw(2) << (unsigned)nat_set[i].number << " |  " << setw(15)
                     << IP_transform(nat_set[i].intra_IP) << "  | " << setw(6)
                     << port_transform(nat_set[i].intra_port) << " | " << setw(6)
                     << port_transform(nat_set[i].firewall_port) << "   |" << endl;
            }
            cout << "——————————————————————————————————————————————\n";
        }
        else if (command == "action") // 6
        {
            char *action = strtok(NULL, " ");
            unsigned char message[3] = "6";
            message[1] = (action[0] == 'Y' ? 1 : 0);
            int ret = netlink_send(socket_fd, message, 3);
        }
        else
        {
            flag = false;
        }
    }

    close(socket_fd);
    system("sudo rmmod firewall");
}

void input_rule(Rule &rule)
{
    string protocol = strtok(NULL, " ");
    rule.protocol = protocol_map.find(protocol)->second;
    if (protocol == "ICMP")
    {
        input_IP(rule.src_IP);
        input_IP(rule.dst_IP);
        rule.src_port = 0;
        rule.dst_port = 0;
    }
    else if (protocol == "TCP" || protocol == "UDP")
    {
        input_IP(rule.src_IP);
        input_port(rule.src_port);
        input_IP(rule.dst_IP);
        input_port(rule.dst_port);
    }
    rule.action = *strtok(NULL, " ");
}

void input_nat(NAT &nat)
{
    input_IP(nat.intra_IP);
    input_port(nat.intra_port);
    input_port(nat.firewall_port);
}

void input_IP(unsigned &IP)
{
    char *temp = strtok(NULL, " ");
    IP = strcmp(temp, "ANY") ? inet_addr(temp) : ANY;
}

void input_port(unsigned short &port)
{
    char *temp = strtok(NULL, " ");
    port = strcmp(temp, "ANY") ? htons(atoi(temp)) : ANY;
}

string find_protocol(unsigned char protocol)
{
    for (map<string, unsigned char>::iterator it = protocol_map.begin(); it != protocol_map.end(); ++it)
    {
        if (it->second == protocol)
        {
            return it->first;
        }
    }
}

string IP_transform(unsigned IP)
{
    if (IP == 0)
    {
        return "ANY";
    }
    else
    {
        struct in_addr addr;
        memcpy(&addr, &IP, 4);
        return inet_ntoa(addr);
    }
}

string port_transform(unsigned short port)
{
    if (port == 0)
    {
        return "ANY";
    }
    else
    {
        return to_string(ntohs(port));
    }
}
