CXX := g++
CXXFLAGS := -std=c++11 -O2 -Wall -pthread
LDLIBS := -lssl -lcrypto

.PHONY: all clean
all: client

client: client.cpp common.h
	$(CXX) $(CXXFLAGS) client.cpp -o client $(LDLIBS)

clean:
	rm -f client
