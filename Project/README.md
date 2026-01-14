
# Design Document: Simple Log Analyzer

**Project Name:** Simple Log Analyzer  
**Group:** 15\
**Contributors** 
| Name             | Roll Number |
|------------------|-------------|
| Abhas Gupta      | 2023017     |
| Akshat Singh     | 2023064     |
| Anushk Kumar     | 2023115     |
| Arhan Jain       | 2023118     |
| Ayush Kitawat    | 2023160     |
```
DEMO VIDEO
https://drive.google.com/drive/folders/1VhOf-bO-C1Gz4z2FfUHMUEViqGLyWhrd?usp=sharing
GITHUB LINK :
https://www.github.com/berserk-23115/LogAnalyser
```
---

## 1. Project Description

### 1.1 Background

Create a lightweight, efficient, and educational log analysis tool that demonstrates:
- Traditional text-based log parsing and analysis
- Real-time network packet capture and inspection
- Anomaly detection through statistical pattern recognition
- Clean C programming practices with minimal external dependencies

### 1.2 Primary Goals

1. **Log Analysis**: Parse and categorize log entries from standard text-based log files
2. **Security Monitoring**: Identify suspicious events based on severity levels and keyword patterns
3. **Network Monitoring**: Capture live network traffic using libpcap
4. **Threat Detection**: Detect potential DDoS attacks through traffic pattern analysis

---

## 2. System Architecture

### 2.1 Execution Modes

The system supports three distinct operational modes:

1. **File Analysis Mode** (default)
   - Input: Text log files
   - Processing: Parse, categorize, flag suspicious entries
   - Output: Statistical summary and suspicious event table

2. **Live Capture Mode**
   - Input: Network interface (via libpcap)
   - Processing: Capture packets, extract IPv4 info, detect DDoS patterns
   - Output: Capture log file + DDoS alerts

3. **Demo Mode**
   - Input: Synthetic traffic definitions
   - Processing: Simulate packet flows, trigger DDoS detector
   - Output: Demo log file + alert demonstrations

---


## 3. Build System & Dependencies

### 3.1 CMake Configuration

#### Build Targets
1. **loganalyzer** (static library)
   - Sources: `log_analyzer.c`, `ddos_detector.c`, `packet_capture.c`
   - Headers: `include/` directory
   - Flags: `-Wall -Wextra -pedantic`

2. **loganalyser** (executable)
   - Sources: `main.c`, `demo.c`
   - Links: loganalyzer library

3. **test_log_analyzer** (test executable)
   - Integrated with CTest

#### Dependency Detection (libpcap)
```cmake
find_package(PCAP QUIET)
if (NOT PCAP_FOUND)
    find_library(PCAP_LIBRARY pcap)
    if (PCAP_LIBRARY)
        set(PCAP_LIBRARIES ${PCAP_LIBRARY})
        set(PCAP_FOUND TRUE)
    endif()
endif()

if (PCAP_FOUND)
    target_link_libraries(loganalyzer PUBLIC ${PCAP_LIBRARIES})
else()
    target_compile_definitions(loganalyzer PUBLIC LOG_ANALYZER_NO_PCAP=1)
    message(WARNING "libpcap not found; live capture mode disabled.")
endif()
```

**Graceful Degradation**
- Missing libpcap → `LOG_ANALYZER_NO_PCAP=1` defined at compile time
- Capture mode stubs return error immediately
- File analysis and demo modes remain fully functional

### 4.2 Platform Support

| Platform | Compiler   | libpcap Availability       | Notes                          |
|----------|------------|----------------------------|--------------------------------|
| macOS    | Clang/GCC  | Built-in                   | No installation required       |
| Linux    | GCC/Clang  | Package manager            | `sudo apt install libpcap-dev` |
| BSD      | GCC/Clang  | Built-in or ports          | Usually pre-installed          |
| Windows  | MSVC/MinGW | WinPcap/Npcap required     | Separate installation needed   |

### 4.3 Build Commands

```bash
# Standard build
cmake -S project-v2 -B project-v2/build
cmake --build project-v2/build

# With specific compiler
cmake -S project-v2 -B project-v2/build -DCMAKE_C_COMPILER=clang
cmake --build project-v2/build

# Run tests
ctest --test-dir project-v2/build --output-on-failure
```

---

## 5. Command-Line Interface

### File Mode (default)
```
--input <path>       Log file to analyze (default: sample-logs/auth.log)
--list-samples       List available sample logs and exit
--help, -h           Show this help message
```

### Live Capture Mode
```
capture [options]
  --iface <name>     Network interface (default: en0)
  --limit <n>        Max packets to capture (default: 500)
  --duration <sec>   Max capture duration in seconds (default: 15)
  --log <path>       Output log file (default: sample-logs/live_capture.log)
  --threshold <n>    DDoS alert threshold (default: 120 packets)
  --window <sec>     DDoS detection window (default: 5 seconds)
```

### Demo Mode
```
run demo test1       Execute built-in demo scenario (test1)
```
