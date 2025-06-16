LDLIBS=-lpcap

all: tls-block


tls-block.o: mac.h ip.h ethhdr.h tcphdr.h tls-block.cpp

tcphdr.o: tcphdr.h tcphdr.cpp

iphdr.o: ip.h iphdr.h iphdr.cpp

ethhdr.o: mac.h ethhdr.h ethhdr.cpp

ip.o: ip.h ip.cpp

mac.o : mac.h mac.cpp

tls-block: tls-block.o tcphdr.o ethhdr.o ip.o mac.o iphdr.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f tls-block *.o
