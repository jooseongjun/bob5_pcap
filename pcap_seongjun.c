#define HAVE_REMOTE



#include<stdio.h>

#include<string.h>

#include "pcap.h"

#pragma comment (lib, "wpcap.lib")



typedef struct ip_address {

	u_char byte1;

	u_char byte2;

	u_char byte3;

	u_char byte4;

}ip_address;



typedef struct ip_header

{

	u_char ver_ihl;

	u_char tos;

	u_short tlen;

	u_short identification; 

	u_short flags_fo; 

	u_char ttl; 

	u_char proto; 

	u_short crc; 

	ip_address saddr; 

	ip_address daddr;

	u_int op_pad; 

}ip_header;



typedef struct udp_header {

	u_short sport; 

	u_short dport;  

	u_short len;  

	u_short crc;  

}udp_header;



struct ether_header

{

	u_char dst_host[6];

	u_char src_host[6];

	u_short frame_type;

}ether_header;

typedef struct tcp_header

{

	u_short sport; 

	u_short dport; 

	u_int seqnum; 

	u_int acknum; 

	u_char hlen; 

	u_char flags; 

	u_short win; 

	u_short crc; 

	u_short urgptr; 

}tcp_header;



void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

int main()

{

	pcap_if_t *alldevs;

	pcap_if_t *d;

	int inum;

	int i = 0;

	pcap_t *adhandle;

	char errbuf[PCAP_ERRBUF_SIZE];

 

	char *filter = "port 80";

	struct bpf_program fcode;

	bpf_u_int32 NetMask;



	if (pcap_findalldevs(&alldevs, errbuf) == -1)

	{

		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);

		exit(1);

	}



	for (d = alldevs; d; d = d->next)

	{

		printf("%d. %s", ++i, d->name);

		if (d->description)

			printf(" (%s)\n", d->description);

		else

			printf(" (No description available)\n");

	}



	if (i == 0)

	{

		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");

		return -1;

	}



	printf("Enter the interface number (1-%d):", i);

	scanf_s("%d", &inum);



	if (inum < 1 || inum > i)

	{

		printf("\nInterface number out of range.\n");



		pcap_freealldevs(alldevs);

		return -1;

	}



	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);



	if ((adhandle = pcap_open_live(d->name, 

		65536,   

		1,    

		1000,   

		errbuf   

		)) == NULL)

	{

		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);

		

		pcap_freealldevs(alldevs);

		return -1;

	}

	printf("\nlistening on %s...\n", d->description);



	NetMask = 0xffffff;



	if (pcap_compile(adhandle, &fcode, filter, 1, NetMask) < 0)

	{

		fprintf(stderr, "\nError compiling filter: wrong syntax.\n");

		pcap_close(adhandle);

		return -3;

	}



	if (pcap_setfilter(adhandle, &fcode)<0)

	{

		fprintf(stderr, "\nError setting the filter\n");

		pcap_close(adhandle);

		return -4;

	}



	pcap_freealldevs(alldevs);



	pcap_loop(adhandle,      

		0,    

		packet_handler,  

		NULL);           

	pcap_close(adhandle);    

	return 0;

}



void packet_handler(u_char *param,                   

	const struct pcap_pkthdr *header, 

	const u_char *pkt_data)           

{

	int i;



	ip_header *ih;

	udp_header *uh;

	tcp_header *th;

	u_int ip_len;



	ih = (ip_header *)(pkt_data + 14); 



	ip_len = (ih->ver_ihl & 0xf) * 4;

	uh = (udp_header *)((u_char*)ih + ip_len);



	printf("Source Mac address : ");

	for (i = 7; i < 12; i++)

	{

		printf("%.2x:", pkt_data[i - 1]);

	}

	printf("%.2x\n", pkt_data[11]);



	printf("Destination Mac address : ");



	for (i = 1; i < 6; i++)

	{

		printf("%.2x:", pkt_data[i - 1]);

	}

	printf("%.2x\n", pkt_data[5]);



	printf("Source IP address : ");

	for (i = 27; i < 30; i++)

	{

		printf("%d.", pkt_data[i - 1]);

	}

	printf("%d\n", pkt_data[29]);



	printf("Destination IP address : ");

	for (i = 31; i < 34; i++)

	{

		printf("%d.", pkt_data[i - 1]);

	}

	printf("%d\n", pkt_data[33]);



	if (ih->proto == 6)

	{

		tcp_header* th;

		th = (tcp_header*) (ih+ip_len);

		printf("Tcp Source Port number : %d\n", (pkt_data[34] * (16*16)) + pkt_data[35]);

		printf("Tcp Destination Port number : %d\n", (pkt_data[36] * (16*16)) + pkt_data[37]);

		

		printf("\n\n\n");

	}

	else if (ih->proto == 17)

	{

		uh = (udp_header*)(uh + ip_len);

		printf("UDP\n");

	}



}
