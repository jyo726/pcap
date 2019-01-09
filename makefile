all: pcap.c pcap1.h
	gcc pcap.c -lpcap -o pcap
