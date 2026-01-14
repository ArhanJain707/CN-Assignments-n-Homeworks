#include <stddef.h>

typedef struct {
    char timestamp[64];
    char level[64];
    char source[64];
    char message[256];
} LogEntry;

typedef struct {
    size_t total;
    size_t info;
    size_t warn;
    size_t error;
    size_t critical;
    size_t suspicious;
} LogStats;

typedef struct {
    char level[64];
    char source[64];
    char message[256];
    char reason[64];
} SuspiciousEvent;

int parse_log_line(const char *line, LogEntry *entry);
size_t load_log_file(const char *path, LogEntry *entries, size_t max_entries);
LogStats summarize_logs(const LogEntry *entries, size_t count);
size_t find_suspicious_events(const LogEntry *entries, size_t count,SuspiciousEvent *events, size_t max_events);
void print_log_summary(const LogStats *stats);
void print_suspicious_events(const SuspiciousEvent *events, size_t count);
