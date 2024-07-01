CXX = g++
CXXFLAGS = -Wall -std=c++14
LDFLAGS = -lsqlite3 -lpcap -pthread

SRCS = main.cpp \
       sbi/DatabaseManager.cpp \
       helpers/Sqlite3Helper.cpp \
       sbi/PacketCapture.cpp \
       sbi/Trigger.cpp \
       sbi/PacketSplit.cpp


INCLUDES = -I sbi/include

# Define the target executable
TARGET = main

# Default rule: build the executable
$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(SRCS) $(LDFLAGS) -o $(TARGET)

# Rule to clean up the directory (remove object files and executable)
clean:
	rm -f $(TARGET)

# Phony targets to avoid conflicts with files of the same name
.PHONY: clean
