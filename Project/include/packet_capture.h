#include "ddos_detector.h"
#include <stddef.h>

typedef struct {
    const char *iface;
    size_t pk_lmt;
    unsigned int dur_sec;
    const char *log_path;
    unsigned int ddos_th;
    unsigned int ddos_wdw_sec;
} CaptureOptions;

typedef struct {
    size_t total_pkt;
    size_t ipv4_pkt;
    size_t logged_pkt;
    size_t errors;
    size_t ddos_alerts;
    DDoSAlert alerts[16];
} CaptureReport;

int capture_live_packets(const CaptureOptions *options, CaptureReport *report);
void print_capture_report(const CaptureOptions *options, const CaptureReport *report);
