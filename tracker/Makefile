CXX := g++
CXXFLAGS := -std=c++11 -O2 -Wall -pthread
LDLIBS := -lssl -lcrypto

.PHONY: all clean
all: tracker

tracker: tracker.cpp common.h
	$(CXX) $(CXXFLAGS) tracker.cpp -o tracker $(LDLIBS)

clean:
	rm -f tracker
