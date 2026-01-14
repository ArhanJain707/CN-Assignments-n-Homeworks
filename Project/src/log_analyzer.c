#include "log_analyzer.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void trim_newline(char *str) { //removing newline character from end of string
    if (!str) return;
    size_t len = strlen(str);
    if (len > 0 && (str[len - 1] == '\n' || str[len - 1] == '\r')) {
        str[len - 1] = '\0'; //swapping with null terminator
    }
}

void to_uppercase(char *str) {
    if (!str) {return;}  
    int i = 0;
    while (str[i]) {
        str[i] = toupper((unsigned char)str[i]);
        i++;
    }
}

int parse_log_line(const char *line, LogEntry *entry){ //filling components of log entry from line
    if (!line || !entry) return 0;

    char timestamp[64];
    char level[64];
    char source[64];
    char message[256];

    int matched = sscanf(line, "%63s %63s %63s %255[^\n]", timestamp, level, source, message);
    if(matched < 4){
        return 0;
    }

    strncpy(entry->timestamp, timestamp, 63);
    entry->timestamp[63] = '\0';
    strncpy(entry->level, level, 63);
    entry->level[63] = '\0';
    strncpy(entry->source, source, 63);
    entry->source[63] = '\0';
    strncpy(entry->message, message, 255);
    entry->message[255] = '\0';

    trim_newline(entry->message); //trimming newline and replacing with null terminator of msg
    return 1;
}

size_t load_log_file(const char *path, LogEntry *entries, size_t max_entries){
    if (!path || !entries || max_entries == 0) return 0;

    FILE *fp = fopen(path, "r"); //opening log file in read mode
    if (!fp) {
        fprintf(stderr, "Could not open log file: %s\n", path);
        return 0;
    }

    size_t count = 0;
    char line[512]; //max number of lines are 512
    while (fgets(line, sizeof(line), fp) && count < max_entries) { //reading a single line here
        if (parse_log_line(line, &entries[count])) { //parsing that line to fill the log entry
            count++;
        }
    }

    fclose(fp); //closing file
    return count; //returning number of lines parsed
}

LogStats summarize_logs(const LogEntry *entries, size_t count) { //returns stats of logs and counts based on levels(types)
    LogStats stats = {0};
    if (!entries) return stats;

    stats.total = count;

    for (size_t i = 0; i < count;++i) {
        char level_copy[64]; //making copy of different levels of logs
        strncpy(level_copy, entries[i].level, sizeof(level_copy));
        level_copy[sizeof(level_copy) - 1] = '\0';
        to_uppercase(level_copy);

        //incrementing count of level depending on the log
        if (strcmp(level_copy, "INFO") == 0) {
            stats.info++;
        } else if (strcmp(level_copy, "WARN") == 0 || strcmp(level_copy, "WARNING") == 0) {
            stats.warn++;
        } else if (strcmp(level_copy, "ERROR") == 0) {
            stats.error++;
        } else if (strcmp(level_copy, "CRITICAL") == 0 || strcmp(level_copy, "FATAL") == 0) {
            stats.critical++;
        }
    }

    return stats;
}

static int contains_keyword(const char *message, const char *keyword) { //checks if a keyword is present in the msg
    if (!message || !keyword) return 0;

    char buffer[256];
    strncpy(buffer, message, sizeof(buffer));
    buffer[sizeof(buffer) - 1] = '\0';
    to_uppercase(buffer);

    char keyword_upper[64];
    strncpy(keyword_upper, keyword, sizeof(keyword_upper));
    keyword_upper[sizeof(keyword_upper) - 1] = '\0';
    to_uppercase(keyword_upper);

    return strstr(buffer, keyword_upper) != NULL;
}

size_t find_suspicious_events(const LogEntry *entries, size_t count, SuspiciousEvent *events, size_t max_events) {
    if (!entries || !events || max_events == 0) return 0;

    const char *keywords[] = {"FAILED", "DENIED", "ERROR", "ATTACK", "TIMEOUT"}; 
    const size_t keyword_count = sizeof(keywords) / sizeof(keywords[0]);

    size_t found = 0;
    for (size_t i = 0; i < count && found < max_events;++i) {
        
        char level_upper[64];
        strncpy(level_upper, entries[i].level, sizeof(level_upper));
        level_upper[sizeof(level_upper) - 1] = '\0';
        to_uppercase(level_upper);
        
        //highlighting entry if level is error or critical or if keywords: FAILED, DENIED, ERROR, ATTACK, TIMEOUT present in msg
        int highlight_level = (strcmp(level_upper, "ERROR") == 0 || strcmp(level_upper, "CRITICAL") == 0); //if error or critical then highlight level = 1
        int highlight_message = 0;

        for (size_t k = 0; k < keyword_count && !highlight_message; ++k) {
            if (contains_keyword(entries[i].message, keywords[k])) { //checking if keyword present in msg
                highlight_message = 1; //then setting highlight message to 1
            }
        }

        if (highlight_level || highlight_message) {
            strncpy(events[found].level, entries[i].level, 63);
            events[found].level[63] = '\0';
            strncpy(events[found].source, entries[i].source, 63);
            events[found].source[63] = '\0';
            strncpy(events[found].message, entries[i].message, 255);
            events[found].message[255] = '\0';
            strncpy(events[found].reason,highlight_level ? "level" : "keyword",63);
            events[found].reason[63] = '\0';
            found++;
        }
    }

    return found;
}

void print_log_summary(const LogStats *stats) {
    if (!stats) return;

    printf("\nLog Summary\n");
    printf("-----------\n");
    printf("Total entries : %zu\n", stats->total);
    printf("Info          : %zu\n", stats->info);
    printf("Warnings      : %zu\n", stats->warn);
    printf("Errors        : %zu\n", stats->error);
    printf("Critical      : %zu\n", stats->critical);
    printf("Suspicious    : %zu\n", stats->suspicious);
}

void print_suspicious_events(const SuspiciousEvent *events, size_t count) {
    if (!events || count == 0) {
        printf("\nNo suspicious events detected.\n");
        return;
    }

    printf("\nSuspicious Events\n");
    printf("-----------------\n");
    for (size_t i = 0; i < count; ++i) {
        printf("[%zu] %-8s %-10s %s\n", i + 1, events[i].level, events[i].source, events[i].message);
    }
}
