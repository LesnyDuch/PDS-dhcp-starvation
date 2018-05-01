CXX=g++
CXXFLAGS=-std=c++11 -Wall

CLIENT_OBJECTS = starvation.o dhcp_client.o
SERVER_OBJECTS = server.o dhcp_server.o
COMMON_OBJECTS = common.o

.PHONY: all clean

all: pds-dhcprogue pds-dhcpstarve

pds-dhcpstarve: $(CLIENT_OBJECTS) $(COMMON_OBJECTS)
	$(CXX) $(CXXFLAGS) $? -o pds-dhcpstarve -lpcap

pds-dhcprogue: $(SERVER_OBJECTS) $(COMMON_OBJECTS)
	$(CXX) $(CXXFLAGS) $(SERVER_OBJECTS) $(COMMON_OBJECTS) -o pds-dhcprogue -lpcap

common.o: common.cpp common.h
dhcp_client.o: dhcp_client.cpp dhcp_client.h common.h
dhcp_server.o: dhcp_server.cpp dhcp_server.h common.h
server.o: server.cpp dhcp_server.h common.h
starvation.o: starvation.cpp dhcp_client.h common.h

clean:
	rm *.o pds-dhcpstarve pds-dhcprogue



