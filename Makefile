pcap_seongjun.o: pcap_seongjun.cpp
	g++ -c -o pcap_seongjun.o pcap_seongjun.cpp
clean:
	rm -f *.o
	rm -f bob5_pcap
