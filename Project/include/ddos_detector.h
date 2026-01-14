#include <stddef.h>
#include <sys/time.h>

typedef struct {
    char source_ip[64];
    size_t packet_count;
    double window_span;
    struct timeval first_seen;
    struct timeval last_seen;
} DDoSAlert;

typedef struct {
    char ip[64];
    size_t count;
    struct timeval window_start;
    struct timeval last_seen;
} SourceBucket;

typedef struct {
    unsigned int threshold;
    unsigned int window_seconds;
    SourceBucket buckets[256];
    size_t bucket_count;
    size_t next_replacement_index;
} DDoSDetector;

void ddos_detector_init(DDoSDetector *detector,unsigned int threshold,unsigned int window_seconds);
int ddos_detector_feed(DDoSDetector *detector,const char *src_ip,const struct timeval *ts,DDoSAlert *alert_out);
void ddos_detector_reset(DDoSDetector *detector);
