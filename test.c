#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/ether.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define BUFSIZE 8192

struct gw_info {
    uint32_t ip;
    unsigned char mac[ETH_ALEN];
};

int send_req(int sock, char *buf, size_t nlseq, size_t req_type)
{
    struct nlmsghdr *nlmsg;

    memset(buf, 0, BUFSIZE); //init
    nlmsg = (struct nlmsghdr *)(buf);

    nlmsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)); //struct rtmsg
    nlmsg->nlmsg_type = req_type; //RTM_GETROUTE or RTM_GETNEIGH
    nlmsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST; //default
    nlmsg->nlmsg_seq = nlseq++; //0
    nlmsg->nlmsg_pid = getpid(); //process id is port

    if (send(sock, buf, nlmsg->nlmsg_len, 0) < 0) //libaray function
        return -1;

    return nlseq; //1
}

int read_res(int sock, char *buf, size_t nlseq)
{
    struct nlmsghdr *nlmsg;
    int len; //current received length
    size_t total_len = 0;

    do {
        len = recv(sock, buf, BUFSIZE - total_len, 0);

        if (len < 0)
            return -1;

        nlmsg = (struct nlmsghdr *)(buf);

        if (NLMSG_OK(nlmsg, len) == 0) //check validation
            return -1;

        if (nlmsg->nlmsg_type == NLMSG_ERROR)
            return -1;

        if (nlmsg->nlmsg_type == NLMSG_DONE) //the end
            break;

        buf += len; //move pointer
        total_len += len;

        if ((nlmsg->nlmsg_flags & NLM_F_MULTI) == 0)
            break;

    } while (nlmsg->nlmsg_seq != nlseq || nlmsg->nlmsg_pid != getpid());

    return total_len;
}

int print_gw(struct gw_info *gw)
{
    char buf[INET_ADDRSTRLEN];

    if (inet_ntop(AF_INET, &gw->ip, buf, INET_ADDRSTRLEN) == NULL)
        return -1;

    printf("gateway ip:  %s\n", buf);
    printf("gateway mac: ");
    for (size_t i = 0; i < ETH_ALEN - 1; ++i)
        printf("%02hhx:", gw->mac[i]);
    printf("%02hhx\n", gw->mac[ETH_ALEN - 1]);

    return 0;
}

void parse_route(struct nlmsghdr *nlmsg, void *gw)
{
    struct rtmsg *rtmsg;
    struct rtattr *attr;
    uint32_t gw_tmp;
    size_t len;
    struct gw_info *info;

    info = (struct gw_info *)(gw);
    rtmsg = (struct rtmsg *)(NLMSG_DATA(nlmsg));

    if (rtmsg->rtm_family != AF_INET || rtmsg->rtm_table != RT_TABLE_MAIN)
        return;

    attr = (struct rtattr *)(RTM_RTA(rtmsg));
    len = RTM_PAYLOAD(nlmsg);

    for (; RTA_OK(attr, len); attr = RTA_NEXT(attr, len)) {
        if (attr->rta_type != RTA_GATEWAY)
            continue;

        info->ip = *((uint32_t *)(RTA_DATA(attr)));
        break;
    }
}

void parse_neigh(struct nlmsghdr *nlmsg, void *gw)
{
    struct ndmsg *ndmsg;
    struct rtattr *attr;
    size_t len;
    char mac[ETH_ALEN];
    uint32_t ip = 0;
    struct gw_info *info;

    info = (struct gw_info *)(gw);
    ndmsg = (struct ndmsg *)(NLMSG_DATA(nlmsg));

    if (ndmsg->ndm_family != AF_INET)
        return;

    attr = (struct rtattr *)(RTM_RTA(ndmsg));
    len = RTM_PAYLOAD(nlmsg);

    for (; RTA_OK(attr, len); attr = RTA_NEXT(attr, len)) {
        if (attr->rta_type == NDA_LLADDR)
            memcpy(mac, RTA_DATA(attr), ETH_ALEN);

        if (attr->rta_type == NDA_DST)
            ip = *((uint32_t *)(RTA_DATA(attr)));
    }

    //if (ip && ip == info->ip)
        memcpy(info->mac, mac, ETH_ALEN);
	memcpy(&info->ip, &ip, 4);
}

void parse_response(char *buf, size_t len, void (cb)(struct nlmsghdr *, void *),
                    void *arg)
{
    struct nlmsghdr *nlmsg;

    nlmsg = (struct nlmsghdr *)(buf);

    for (; NLMSG_OK(nlmsg, len); nlmsg = NLMSG_NEXT(nlmsg, len))
        cb(nlmsg, arg);
}

int main(int argc, char **argv)
{
    int sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    char buf[BUFSIZE];
    size_t nlseq = 0;
    size_t msg_len;
    struct gw_info gw;

    if (sock <= 0)
        return -1;

	//RTM_GETROUTE -> gateway ip
    /*nlseq = send_req(sock, buf, nlseq, RTM_GETROUTE); //first, send the request
    msg_len = read_res(sock, buf, nlseq); //second, receive the response

    if (msg_len <= 0)
        return -1;

    parse_response(buf, msg_len, &parse_route, &gw);*/

	//RTM_GETNEIGH -> gateway mac
    nlseq = send_req(sock, buf, nlseq, RTM_GETNEIGH);
    msg_len = read_res(sock, buf, nlseq);

    if (msg_len <= 0)
        return -1;

    parse_response(buf, msg_len, &parse_neigh, &gw);
    print_gw(&gw);

    return 0;

}

//https://hundeboll.net/getting-the-gateway-link-layer-address-using-rtnetlink.html
