#include "demo.h"

#include "ddos_detector.h"

#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

typedef struct {
    const char *source;
    const char *destination;
    size_t packets;
    unsigned int step_ms;
} DemoFlow;

static void advance_time(struct timeval *ts, unsigned int step_ms) { //increasing time by step_ms ms
    if (!ts) return;
    long delta = (long)step_ms * 1000;
    ts->tv_usec += delta;
    while (ts->tv_usec >= 1000000) {
        ts->tv_usec -= 1000000;
        ts->tv_sec += 1;
    }
}

static void format_timestamp(const struct timeval *ts, char *buffer, size_t len){ //converting so that timestamp is human readable
    if (!ts || !buffer || len == 0) return;
    time_t seconds = ts->tv_sec;
    struct tm tm_info;
    gmtime_r(&seconds, &tm_info);
    strftime(buffer, len, "%Y-%m-%dT%H:%M:%S", &tm_info);
}

int run_demo_test1(void) { //running the demo
    const char *log_path = "sample-logs/demo_test1.log"; //path to demo log
    FILE *fp = fopen(log_path, "w"); 
    if (!fp) {
        perror("demo log");
        return 1;
    }

    printf("Running demo test1: synthesised packet burst to showcase DDoS detector.\n"); //printing
    printf(" Output log: %s\n", log_path); //print output log path

    DemoFlow flows[] = {{"10.10.10.5", "192.168.1.10", 25, 80},{"203.0.113.44", "192.168.1.10", 120, 5},{"10.10.10.8", "192.168.1.20", 30, 60}};
    const size_t flow_count = sizeof(flows) / sizeof(flows[0]);

    DDoSDetector detector;
    ddos_detector_init(&detector, 60, 5); //initializing ddos detector

    struct timeval ts = {.tv_sec = 1700000000, .tv_usec = 0}; //setting time values here
    size_t total_packets = 0;
    size_t alerts = 0;

    for (size_t i = 0; i < flow_count; ++i) {
        const DemoFlow *flow = &flows[i];
        for (size_t p = 0; p < flow->packets; ++p) { //iterating through packets
            char timestamp[32];
            format_timestamp(&ts, timestamp, sizeof(timestamp)); //formatting the timestamp
            fprintf(fp, "%s %s -> %s proto=UDP len=512\n", timestamp,flow->source, flow->destination);

            DDoSAlert alert;
            if (ddos_detector_feed(&detector, flow->source, &ts, &alert)) { //checking for ddos attack from ip
                ++alerts;
                char first[32];
                char last[32];
                format_timestamp(&alert.first_seen, first, sizeof(first));
                format_timestamp(&alert.last_seen, last, sizeof(last));
                printf(" Alert #%zu: offender %s sent %zu packets within %.2fs (%s -> %s)\n",alerts,alert.source_ip,alert.packet_count,alert.window_span,first,last);
            }

            advance_time(&ts, flow->step_ms); //advancing time for next flow
            total_packets++;
        }
    }

    fclose(fp); //closing descriptor
    printf(" Demo finished: %zu packets replayed, %zu alerts raised.\n", total_packets, alerts);
    return 0;
}
