cmake_minimum_required(VERSION 3.16)
project(SimpleLogAnalyser C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_library(loganalyzer STATIC
	src/log_analyzer.c
	src/ddos_detector.c
	src/packet_capture.c
)
target_include_directories(loganalyzer PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_compile_options(loganalyzer PRIVATE -Wall -Wextra -pedantic)

add_executable(loganalyser src/main.c src/demo.c)
target_link_libraries(loganalyser PRIVATE loganalyzer)

find_package(PCAP QUIET)
if (NOT PCAP_FOUND)
	find_library(PCAP_LIBRARY pcap)
	if (PCAP_LIBRARY)
		set(PCAP_LIBRARIES ${PCAP_LIBRARY})
		set(PCAP_FOUND TRUE)
	endif()
endif()

if (PCAP_FOUND)
	if (PCAP_INCLUDE_DIRS)
		target_include_directories(loganalyzer PRIVATE ${PCAP_INCLUDE_DIRS})
	endif()
	target_link_libraries(loganalyzer PUBLIC ${PCAP_LIBRARIES})
else()
	message(WARNING "libpcap not found; live capture mode disabled.")
endif()

enable_testing()
add_subdirectory(tests)
