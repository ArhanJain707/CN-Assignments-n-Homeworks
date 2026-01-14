#include "ddos_detector.h"
#include <string.h>

static double diff_seconds(const struct timeval *a, const struct timeval *b) { //returning duration
    if (!a || !b) return 0.0;
    double sec = (double)(a->tv_sec - b->tv_sec);
    double usec = (double)(a->tv_usec - b->tv_usec) / 1e6;
    return sec + usec;
}

static SourceBucket *find_bucket(DDoSDetector *detector, const char *src_ip) { //finding bucket where source id is present
    if(!detector || !src_ip)return NULL;
    for(size_t i = 0; i < detector->bucket_count; ++i){
        if(strncmp(detector->buckets[i].ip, src_ip, sizeof(detector->buckets[i].ip)) == 0){
            return &detector->buckets[i];
        }
    }
    return NULL;
}

static SourceBucket *alloc_bucket(DDoSDetector *detector, const char *src_ip, const struct timeval *ts) { //allocating memory for bucket and setting up
    if (!detector || !src_ip || !ts) return NULL;

    SourceBucket *slot = NULL;
    if (detector->bucket_count < 256) {
        slot = &detector->buckets[detector->bucket_count++];
    } else {
        slot = &detector->buckets[detector->next_replacement_index];
        detector->next_replacement_index = (detector->next_replacement_index + 1) % 256;
    }

    strncpy(slot->ip, src_ip, sizeof(slot->ip) - 1); //copying the source ip to bucket
    slot->ip[sizeof(slot->ip) - 1] = '\0';
    slot->count = 0; //count is number of packets from the src ip
    slot->window_start = *ts; //starting time of window (of appearance of IP)
    slot->last_seen = *ts; //src ip last seen
    return slot;
}

void ddos_detector_init(DDoSDetector *detector, unsigned int threshold, unsigned int window_seconds) { //initializing detector
    if (!detector) return;
    detector->threshold = threshold;
    detector->window_seconds = window_seconds;
    detector->bucket_count = 0;
    detector->next_replacement_index = 0;
}

void ddos_detector_reset(DDoSDetector *detector) { //resetting detector
    if (!detector) return;
    detector->bucket_count = 0;
    detector->next_replacement_index = 0;
}

int ddos_detector_feed(DDoSDetector *detector,const char *src_ip, const struct timeval *ts, DDoSAlert *alert_out) {
    if (!detector || !src_ip || !ts) return 0;

    SourceBucket *bucket = find_bucket(detector, src_ip); //finds bucket which contains source ip
    if (!bucket) {
        bucket = alloc_bucket(detector, src_ip, ts); //allocates new bucket if not found
    }

    if (!bucket) return 0;

    double elapsed = diff_seconds(ts, &bucket->window_start);
    if(elapsed > detector->window_seconds){ //if time window more than window_seconds, then reset count and window start time
        bucket->window_start = *ts;
        bucket->count = 0;
    }

    bucket->last_seen = *ts; //updating last time we saw the IP
    bucket->count++; //increasing number of packets counted from this source ip in this window

    if(bucket->count >= detector->threshold){ //number of packets exceeding amount that we allowed
        if (alert_out) {
            DDoSAlert alert; //filling alert details
            strncpy(alert.source_ip, bucket->ip, sizeof(alert.source_ip) - 1);
            alert.source_ip[sizeof(alert.source_ip) - 1] = '\0';
            alert.packet_count = bucket->count;
            alert.first_seen = bucket->window_start;
            alert.last_seen = bucket->last_seen;
            alert.window_span = diff_seconds(&bucket->last_seen, &bucket->window_start);
            *alert_out = alert;
        }
        bucket->count = 0;
        bucket->window_start = *ts;
        return 1;
    }

    return 0;
}
