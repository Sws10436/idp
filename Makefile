CXX = g++
CXXFLAGS = -std=c++20 -O2 -Wall -Wextra -Iinclude
LDFLAGS = -lws2_32 -liphlpapi -lpsapi -ladvapi32

SRC = src/main.cpp src/privilege.cpp src/process_collector.cpp src/memory_scanner.cpp src/network_mapper.cpp src/json_serializer.cpp
TARGET = bin/telemetry_engine.exe

all: $(TARGET)

$(TARGET): $(SRC)
	@if not exist bin mkdir bin
	$(CXX) $(CXXFLAGS) $(SRC) $(LDFLAGS) -o $(TARGET)

clean:
	@if exist bin rmdir /s /q bin

.PHONY: all clean
