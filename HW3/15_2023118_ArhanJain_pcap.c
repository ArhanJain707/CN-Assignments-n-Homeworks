// Source: https://www.devdungeon.com/content/using-libpcap-c

#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <string.h>
#include <assert.h>

#include <stdio.h>
#include <netinet/ip.h>


#define MAX_NAME_LEN 280

struct dns_q {
	__be16 type;
	__be16 class;  // 1 for Internet
};

struct dns_rr {
	__be16 type;
	__be16 class;  // 1 for Internet
	__be32 ttl;
	__be16 rlen;
	unsigned char rdata[]; // variable length rdata
};

struct dns_header {
	__be16 id;
	__be16 flags;
	__be16 num_ques; // Number of questions
	__be16 num_ans;  // Number of answers RRs
	__be16 num_auth; // Number of authority RRs
	__be16 num_add;  // Number of additional RRs
};

// copy name in the DNS message into argument name
// argument len is the length of the buffer name
// start is the starting address where the name is stored
// msg_start is the starting address of the DNS message
// Rough pseudocode
/***
1. off = ntohs(*(__be16*)start);
2. if ((off >> 14) == 3):
3.	 string is stored at (off & 0x3FFF)
4.	 rest of the record at start + 2
5. else:
6.   length of label at start[0]
7.	 if length is zero, the rest of the record starts at start + 1
8.	 otherwise; goto step-1 after reading len bytes into name and advancing start appropriately
***/


unsigned char* print_helper(unsigned char *start, unsigned char *msg_start, char *name, size_t len)
{
	unsigned char *curr_pos = start, *return_pos = start;
	int is_compressed = 0;
	while((char)*curr_pos != 0){
		uint16_t offset = ntohs(*(__be16*)curr_pos);
		if ((offset >> 14) == 3){
			if (is_compressed == 0){
				return_pos = curr_pos + 2;
				is_compressed = 1;}
			curr_pos = msg_start + (offset & 0x3FFF);}

		else {
			int length = (int)*curr_pos;
			curr_pos++;
			for (int i = 0; i < length; i++)
				*name++ = (char)*curr_pos++;
			*name++ = '.';}}
		if (is_compressed == 0)
			return_pos = curr_pos + 1;
	*name = '\0';
	return return_pos;
}

unsigned char* print_name(unsigned char *start, unsigned char *msg_start)
{
	char name[MAX_NAME_LEN];
	unsigned char *ret = print_helper(start, msg_start, name, MAX_NAME_LEN);
	printf("%s ", name);
	return ret;
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	struct ethhdr *eth;
	eth = (struct ethhdr *) packet;
	if (ntohs(eth->h_proto) != ETHERTYPE_IP) {
		return;
	}

	struct iphdr *iph = (struct iphdr*)((char*)eth + sizeof(struct ethhdr));

	if (iph->protocol != IPPROTO_UDP) {
		// not a UDP packet
		return;
	}

	struct udphdr *udp = (struct udphdr*)((char*)iph + (iph->ihl * 4));

	if (udp->source != htons(53) && udp->dest != htons(53)) {
		// not a DNS packet
		return;
	}

	unsigned char *msg_start = (unsigned char*)udp + sizeof(struct udphdr);
	struct dns_header *dnshdr = (struct dns_header*)(msg_start);
	int id = (int)ntohs(dnshdr->id);
	int flags = (int)ntohs(dnshdr->flags);
	int num_ques = (int)ntohs(dnshdr->num_ques);
	int num_ans = (int)ntohs(dnshdr->num_ans);
	int num_auth = (int)ntohs(dnshdr->num_auth);
	int num_add = (int)ntohs(dnshdr->num_add);

	printf("\n-------------------- START -----------------------\n");
	printf("\nid: %d flags: %d num_questions: %d num_answers: %d num_authority: %d num_additional: %d\n",
		id, flags, num_ques, num_ans, num_auth, num_add);

	int i;
	unsigned char *start = ((unsigned char*)dnshdr + sizeof(struct dns_header));


	printf("\nprinting question section\n");
	for (i = 0; i < num_ques; i++) {
		unsigned char *end = print_name(start, msg_start);
		struct dns_q *dq = (struct dns_q*)(end);
		printf("type: %hx class: %hx\n", htons(dq->type), htons(dq->class));
		// write your code here
		// initialize start to the address of the next record
		//start =
		start = (unsigned char*)dq + sizeof(struct dns_q);
	}

	printf("\nprinting answer section\n");
	for (i = 0; i < num_ans; i++) {
		unsigned char *end = print_name(start, msg_start);
		struct dns_rr *dr = (struct dns_rr*)(end);
		printf("type: %hx class: %hx ttl: %x len: %hx\n", ntohs(dr->type), ntohs(dr->class), ntohl(dr->ttl), ntohs(dr->rlen));
		// write your code here
		// initialize start to the address of the next record
		// skip rdata
		//start =
		start = (unsigned char*)dr->rdata + ntohs(dr->rlen);
	}

	printf("\nprinting authority section\n");
	for (i = 0; i < num_auth; i++) {
		unsigned char *end = print_name(start, msg_start);
		struct dns_rr *dr = (struct dns_rr*)(end);
		printf("type: %hx class: %hx ttl: %x len: %hx\n", ntohs(dr->type), ntohs(dr->class), ntohl(dr->ttl), ntohs(dr->rlen));
		// write your code here
		// initialize start to the address of the next record
		// skip rdata
		//start =
		start = (unsigned char*)dr->rdata + ntohs(dr->rlen);
	}

	printf("\nprinting additional section\n");
	for (i = 0; i < num_add; i++) {
		unsigned char *end = print_name(start, msg_start);
		struct dns_rr *dr = (struct dns_rr*)(end);
		printf("type: %hx class: %hx ttl: %x len: %hx\n", ntohs(dr->type), ntohs(dr->class), ntohl(dr->ttl), ntohs(dr->rlen));
		// write your code here
		// initialize start to the address of the next record
		// skip rdata
		//start =
		start = (unsigned char*)dr->rdata + ntohs(dr->rlen); 
	}

	printf("\n-------------------- END -----------------------\n");
}

int main(int argc, char *argv[])
{
	pcap_t *handle;			/* Session handle */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	pcap_if_t *alldevs;
	pcap_if_t *d;

	// Find all devices
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		fprintf(stderr, "Error finding devices: %s\n", errbuf);
		return 1;
	}

	if (alldevs == NULL) {
		fprintf(stderr, "no available device\n");
		return 1;
	}

	// Print the list
	printf("Available network interfaces:\n");
	for (d = alldevs; d != NULL; d = d->next) {
		printf("%s", d->name);
		if (d->description) {
			printf(" - %s\n", d->description);
		}
		else {
			printf(" - No description available\n");
		}
	}
	/* Define the device */
	handle = pcap_open_live(alldevs->name, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open default device: %s\n", alldevs->name);
		pcap_freealldevs(alldevs);
		return(2);
	}
	printf("Could open: %s\n", alldevs->name);

	pcap_loop(handle, 0, packet_handler, NULL);

	/* And close the session */
	pcap_close(handle);
	pcap_freealldevs(alldevs);
	return(0);
}
