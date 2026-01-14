#include "log_analyzer.h"
#include "ddos_detector.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

static void test_parse_line(void) {
    LogEntry entry;
    int ok = parse_log_line("2025-11-18T10:00:00Z INFO api Request completed", &entry);
    assert(ok);
    assert(strcmp(entry.level, "INFO") == 0);
    assert(strcmp(entry.source, "api") == 0);
}

static void test_suspicious_detection(void) {
    LogEntry entries[2];
    parse_log_line("2025-11-18T10:01:00Z ERROR auth Login failed", &entries[0]);
    parse_log_line("2025-11-18T10:02:00Z INFO api Request completed", &entries[1]);

    SuspiciousEvent events[2];
    size_t count = find_suspicious_events(entries, 2, events, 2);
    assert(count == 1);
    assert(strcmp(events[0].level, "ERROR") == 0);
}

static void test_ddos_detector(void) {
    DDoSDetector detector;
    ddos_detector_init(&detector, 5, 2);

    struct timeval ts = {.tv_sec = 0, .tv_usec = 0};
    int triggered = 0;

    for (int i = 0; i < 5; ++i) {
        ts.tv_usec = (i * 100000) % 1000000;
        DDoSAlert alert;
        if (ddos_detector_feed(&detector, "198.51.100.10", &ts, &alert)) {
            triggered = 1;
            assert(alert.packet_count == 5);
            break;
        }
    }

    assert(triggered);

    ts.tv_sec += 5;
    DDoSAlert alert;
    int second_alert = ddos_detector_feed(&detector, "198.51.100.10", &ts, &alert);
    assert(second_alert == 0);
}

int main(void) {
    test_parse_line();
    test_suspicious_detection();
    test_ddos_detector();
    printf("All log analyzer tests passed.\n");
    return 0;
}
