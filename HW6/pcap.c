// Source: https://www.devdungeon.com/content/using-libpcap-c

#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <string.h>
#include <assert.h>

#include <stdio.h>
#include <netinet/ip.h>


// options points to the first byte of TCP header options
// len is the length of the TCP header options
// print TCP SACK acknowledgements in this routine
int kind5_count = 1;
void print_tcp_options(unsigned char *options, size_t len){
	int kind = options[0], i = 0;

	while (i < len && kind != 0){
		if (kind == 1){ //nop
			i++;}
		else if (kind > 1){
			int lenth = options[i + 1];
			if (kind == 5){
				int num_ranges = (lenth - 2) / 8;
				printf("Kind 5 count : %d, Num of ranges : %d\n", kind5_count++, num_ranges);
				for (int j = 0; j < num_ranges; j++){
					int start = ntohl(*((unsigned int *) (options + i + 2 + j * 8)));
					int end = ntohl(*((unsigned int *) (options + i + 6 + j * 8)));
					printf("start : %u, end : %u\n", start, end);}}
				i += lenth;}
		if (i < len)	
			kind = options[i];
		else
			kind = 0;}}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	struct ethhdr *eth;
	eth = (struct ethhdr *) packet;
	if (ntohs(eth->h_proto) != ETHERTYPE_IP) {
		return;
	}

	struct iphdr *iph = (struct iphdr*)((char*)eth + sizeof(struct ethhdr));

	if (iph->protocol != IPPROTO_TCP) {
		// not a TCP packet
		return;
	}
	struct tcphdr *tcp = (struct tcphdr*)((char*)iph + (iph->ihl * 4));
	int length = tcp->doff * 4;
	if (length > 20) {
		unsigned char *options = (((unsigned char*)tcp) + 20);
		print_tcp_options(options, length - 20);
	}
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
