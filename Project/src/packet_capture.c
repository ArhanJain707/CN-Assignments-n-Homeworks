#include "packet_capture.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <pcap/pcap.h>


#define ETHERTYPE_IPV4 0x0800

static double elapsed_seconds(const struct timeval *a, const struct timeval *b) { //Calculating time between a and b
    if (!a || !b) return 0.0;
    double sec = (double)(a->tv_sec - b->tv_sec);
    double usec = (double)(a->tv_usec - b->tv_usec)/1e6;
    return sec + usec;
}

static void format_timestamp(const struct timeval *ts, char *buffer, size_t len) { //converting timestamp to be human readable
    if (!ts || !buffer || len == 0) return;
    time_t seconds = ts->tv_sec;
    struct tm tm_info;
    gmtime_r(&seconds, &tm_info);
    strftime(buffer, len, "%Y-%m-%dT%H:%M:%S", &tm_info);
}

static const char *protocol_name(uint8_t proto) { //returning name of the protocol
    switch (proto) {
        case IPPROTO_TCP:
            return "TCP";
        case IPPROTO_UDP:
            return "UDP";
        case IPPROTO_ICMP:
            return "ICMP";
        default:
            return "OTHER";
    }
}

static void persist_packet(FILE *fp, const struct timeval *ts, const char *src, const char *dst, size_t length, uint8_t proto){ //printing formatted timestamps
    if (!fp) return;
    char timestamp[32];
    format_timestamp(ts, timestamp, sizeof(timestamp));
    fprintf(fp, "%s %s -> %s proto=%s len=%zu\n",timestamp, src, dst, protocol_name(proto), length);
}

static void store_alert(CaptureReport *report, const DDoSAlert *alert) { //if ddos alert comes, increasing alert number
    if (!report || !alert) return;
    if (report->ddos_alerts >= 16) return;
    report->alerts[report->ddos_alerts++] = *alert;
}

static int handle_packet(const u_char *packet, const struct pcap_pkthdr *header, FILE *fp, DDoSDetector *detector, CaptureReport *report) {
    if (!packet || !header || !report) return 0;
    if (header->caplen < 14 + sizeof(struct ip)) return 0; //checking if header length is less than ethernet header length + ip header len

    uint16_t ethKind = (uint16_t)((packet[12] << 8) | packet[13]); //checking type of ethernet
    if (ethKind != ETHERTYPE_IPV4) return 0; //if ethernet is not ipv4, returning 0 as tool is only for ipv4

    const struct ip *ip_header = (const struct ip *)(packet + 14); //accessing ip header
    char src_ip[16];
    char dst_ip[16];

    if (!inet_ntop(AF_INET, &ip_header->ip_src, src_ip, sizeof(src_ip))) return 0;
    if (!inet_ntop(AF_INET, &ip_header->ip_dst, dst_ip, sizeof(dst_ip))) return 0;

    report->ipv4_pkt++; //incrementing number of packets in report
    persist_packet(fp, &header->ts, src_ip, dst_ip, header->len, ip_header->ip_p); //printing packet details to log file
    if(fp){
        report->logged_pkt++; //increasing logged packets if file descriptor valid
    }

    if(detector){ //if ddos detector valid
        DDoSAlert alert;
        if(ddos_detector_feed(detector, src_ip, &header->ts, &alert)){//if ddos detector feed returns 1, i.e. ddos attack detected
            store_alert(report, &alert); //store the ddos alert in report
        }
    }

    return 1;
}

int capture_live_packets(const CaptureOptions *options, CaptureReport *report){
    if (!options || !report) return -1;
    memset(report, 0, sizeof(*report));

    char errbuf[PCAP_ERRBUF_SIZE]; //to store error messages
    const char *iface = options->iface ? options->iface : "en0"; //putting interface name
    pcap_t *handle = pcap_open_live(iface, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "Unable to open interface %s: %s\n", iface, errbuf);
        return -1;
    }

    FILE *fp = NULL;
    if (options->log_path) { //if path to log file there in options
        fp = fopen(options->log_path, "w"); //opening the file
        if (!fp) {
            perror("capture log");
            pcap_close(handle);
            return -1;
        }
    }

    DDoSDetector detector;
    ddos_detector_init(&detector, options->ddos_th ? options->ddos_th : 100, options->ddos_wdw_sec ? options->ddos_wdw_sec : 5); //initializing ddos detector with threshold and window seconds, setting bucket and count to 0

    struct timeval start_ts = {0};
    int started = 0;
    size_t pk_lmt = options->pk_lmt ? options->pk_lmt : 500;

    while (report->total_pkt < pk_lmt) {
        const u_char *packet = NULL;
        struct pcap_pkthdr *header = NULL;
        int status = pcap_next_ex(handle, &header, &packet); //trying to read next packet
        if (status == 0) { //if next packet not yet ready
            continue;
        } else if (status == -1) {
            fprintf(stderr, "pcap_next_ex error: %s\n", pcap_geterr(handle));
            report->errors++; //increasing count for errors
            break;
        } else if (status == -2) {
            break;
        }
        if(!started){ 
            start_ts = header->ts; //time struct of first packet
            started = 1; //setting started to 1
        }
        if (options->dur_sec > 0) {
            double span = elapsed_seconds(&header->ts, &start_ts); //time taken for this packet since first packet
            if (span > options->dur_sec) { //no more processing if time more than duration seconds assigned
                break;
            }
        }

        report->total_pkt++;
        handle_packet(packet, header, fp, &detector, report); //send to handler
    }

    if (fp) {
        fclose(fp); //closing file pointer here
    }
    pcap_close(handle); //closing pcap handle here
    return 0;
}

void print_capture_report(const CaptureOptions *options, const CaptureReport *report) {
    if (!report) return;

    printf("\nLive Capture Summary\n");
    printf("--------------------\n");
    if (options && options->iface) {
        printf("Interface     : %s\n", options->iface);
    }
    printf("Packets seen  : %zu\n", report->total_pkt);
    printf("IPv4 packets  : %zu\n", report->ipv4_pkt);
    if (report->logged_pkt) {
        printf("Logged lines  : %zu\n", report->logged_pkt);
    }
    printf("Errors        : %zu\n", report->errors);
    printf("DDoS alerts   : %zu\n", report->ddos_alerts);

    for (size_t i = 0; i < report->ddos_alerts;++i) {
        const DDoSAlert *alert = &report->alerts[i];
        char first_buf[32];
        char last_buf[32];
        format_timestamp(&alert->first_seen, first_buf, sizeof(first_buf));
        format_timestamp(&alert->last_seen, last_buf, sizeof(last_buf));
        printf("  #%zu offender=%s packets=%zu window=%.2fs [%s -> %s]\n", i + 1, alert->source_ip, alert->packet_count, alert->window_span, first_buf, last_buf);
    }
}
