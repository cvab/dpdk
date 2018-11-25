/* 
 *  File: netlink_raw.c 
 *
 */ 

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>

#define DEFAULT_IF	"eth0"
#define BUF_SIZ		1024

static inline
uint16_t ip_hdr_csum(const void *buff, size_t len)
{
    const uint16_t *buf=buff;
    size_t byte_len=len;
    uint32_t sum = 0;

    /* Calculate the sum */
    sum = 0;
    while (byte_len > 1)
    {
        sum += *buf++;
        if (sum & 0x80000000)
            sum = (sum & 0xFFFF) + (sum >> 16);
        byte_len -= 2;
    }

    /* Add the carries */
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    /* Return the one's complement of sum */
    return ((uint16_t)(~sum));
}

int main(int argc, char *argv[])
{
	char sender[INET6_ADDRSTRLEN];
	uint16_t lcl_port;
	int sockfd, ret, i;
	int sockopt;
	ssize_t numbytes;
	struct ifreq ifopts;	/* set promiscuous mode */
	struct ifreq if_ip;	 /* get ip addr */
	struct sockaddr_storage their_addr;
	uint8_t buf[BUF_SIZ];
	char ifName[IFNAMSIZ];
	
	/* Get interface name */
	if (argc > 1)
		strcpy(ifName, argv[1]);
	else
		strcpy(ifName, DEFAULT_IF);

	const unsigned char ether_broadcast_addr[]=
        {0xff,0xff,0xff,0xff,0xff,0xff};

	/* Header structures */
	struct ether_header *eh = (struct ether_header *) buf;
	struct iphdr *iph = (struct iphdr *) (buf + sizeof(struct ether_header));
	struct udphdr *udph = (struct udphdr *) (buf + sizeof(struct iphdr) + sizeof(struct ether_header));
	struct icmphdr *icmph = (struct icmphdr *) (buf + sizeof(struct iphdr) + sizeof(struct ether_header));

	memset(&if_ip, 0, sizeof(struct ifreq));

	/* Open PF_PACKET socket, listening for EtherType ETH_P_IP */
	if ((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) == -1) {
		perror("listener: socket");	
		return -1;
	}

	/* Set interface to promiscuous mode - do we need to do this every time? */
	strncpy(ifopts.ifr_name, ifName, IFNAMSIZ-1);
	ioctl(sockfd, SIOCGIFFLAGS, &ifopts);
	ifopts.ifr_flags |= IFF_PROMISC;
	ioctl(sockfd, SIOCSIFFLAGS, &ifopts);

	/* Allow the socket to be reused - incase connection is closed prematurely */
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof sockopt) == -1) {
		perror("setsockopt");
		close(sockfd);
		exit(EXIT_FAILURE);
	}

	/* Bind to device */
    struct sockaddr_ll lcl_addr, dest_addr;  
	unsigned char *ether_lcl_addr;

	ioctl(sockfd, SIOCGIFHWADDR, &ifopts);
	ether_lcl_addr = (unsigned char*)ifopts.ifr_hwaddr.sa_data;
    lcl_addr.sll_family=AF_PACKET;
	ioctl(sockfd, SIOCGIFINDEX, &ifopts);
    lcl_addr.sll_ifindex=ifopts.ifr_ifindex;
    lcl_addr.sll_halen=ETHER_ADDR_LEN;
    lcl_addr.sll_protocol=htons(ETH_P_IP);
    memcpy(lcl_addr.sll_addr,ether_lcl_addr,ETHER_ADDR_LEN);
    if (bind(sockfd, (struct sockaddr *)&lcl_addr, sizeof(struct sockaddr_ll)) < 0)
    {
        printf("bind failed");
        return -1;
    }

	while (1) {	
		printf("listener: Waiting to recvfrom...\n");
		numbytes = recvfrom(sockfd, buf, BUF_SIZ, 0, NULL, NULL);
		printf("listener: got packet %lu bytes\n", numbytes);

		if (numbytes <= 0) continue;

		/* Print packet */
		printf("\e[1m \t Rx Packet Data:\n \e[m");
		for (i=0; i<numbytes; i++) { 
			printf("%02x: ", buf[i]);
			if ((i % 16) == 15) printf("\n");
		}
		printf("\n"); 

		/* Get source IP */
		((struct sockaddr_in *)&their_addr)->sin_addr.s_addr = iph->saddr;
		inet_ntop(AF_INET, &((struct sockaddr_in*)&their_addr)->sin_addr, sender, sizeof sender);

		/* Look up my device IP addr if possible */
		strncpy(if_ip.ifr_name, ifName, IFNAMSIZ-1);
		if (ioctl(sockfd, SIOCGIFADDR, &if_ip) >= 0) { /* if we can't check then don't */
			printf("Source IP : %s\nMy  IP    : %s\n", sender, 
					inet_ntoa(((struct sockaddr_in *)&if_ip.ifr_addr)->sin_addr));
			/* ignore if I sent it */
			if (strcmp(sender, inet_ntoa(((struct sockaddr_in *)&if_ip.ifr_addr)->sin_addr)) == 0)	{
				printf("but I sent it :(\n");
				ret = -1;
				continue;
			}
		}

		/* Reflect it back on the same interface */	
		if (eh->ether_type == htons(ETH_P_IP)) { 
			if (iph->protocol == 17) { /* UDP */
				lcl_port = udph->dest;
				udph->dest = udph->source; 
				udph->source = lcl_port; 
			} else if (iph->protocol == 0x1) { /* ICMP */
				if (icmph->type == ICMP_ECHO)  
					icmph->type = ICMP_ECHOREPLY; /* Echo reply */
			}

			iph->saddr = iph->daddr;
			iph->daddr = ((struct sockaddr_in *)&their_addr)->sin_addr.s_addr;
			/* iph->saddr = ((struct sockaddr_in *)&if_ip.ifr_addr)->sin_addr.s_addr;  */
			iph->check = 0; /* pseudo checksum */
			iph->check = ip_hdr_csum(buf + sizeof(struct ether_header), 
							sizeof(struct iphdr));  
		} 
		uint8_t mac_addr[6]; 
		memcpy(mac_addr, &eh->ether_dhost[0], ETHER_ADDR_LEN);
		memcpy(&eh->ether_dhost[0], &eh->ether_shost[0], ETHER_ADDR_LEN);
		memcpy(&eh->ether_shost[0], mac_addr, ETHER_ADDR_LEN);

		/* Print packet */
		printf("\e[1m \t Tx Packet Data:\n \e[m");
		for (i=0; i<numbytes; i++) { 
			printf("%02x: ", buf[i]);
			if ((i % 16) == 15) printf("\n");
		}
		printf("\n"); 
		dest_addr.sll_family=AF_PACKET;
		dest_addr.sll_ifindex=ifopts.ifr_ifindex;
		dest_addr.sll_halen=ETHER_ADDR_LEN;
		dest_addr.sll_protocol=htons(ETH_P_IP);
		memcpy(dest_addr.sll_addr,ether_broadcast_addr,ETHER_ADDR_LEN);
		if(sendto(sockfd, buf, numbytes, 0, 
					(struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0)
		{
			perror("sendto() error");
			exit(-1);
		}
	}
 
	close(sockfd);
	return 0;
}
