CC := gcc
SRC := sniff.c pktparse.c
EXE := sniff

ARP_SRC := arp.c util.c
ARP_EXE := arp

WLESS_SRC := wireless.c util.c pktparse.c
WLESS_EXE := wireless

ICMP_SRC := icmp.c util.c

LIST := list

sniff : $(SRC)
	$(CC) $(SRC) -o $(EXE)

arp : $(ARP_SRC)
	$(CC) $(ARP_SRC) -o $(ARP_EXE) -lpthread

wireless : $(WLESS)
	$(CC) $(WLESS_SRC) -o $(WLESS_EXE)

icmp : $(ICMP_SRC)
	$(CC) $(ICMP_SRC) -o icmp

vendor-update :
	#first, create 'list' file that has unknown mac address of vendor
	#ex) ./arp 'eth0' hostscan > sample
	#ex) ./retparse sample > list
	#second, take "make vendor-update"
	./vendor_finder.php $(subst $(LIST),,$(shell wc -w $(LIST))) < $(LIST) >> mac-vendor.txt

clean :
	rm -f $(EXE) $(ARP_EXE) $(WLESS_EXE) icmp


#git add -A
#git commit -m "file name"
#git push

#git pull

#git clone https://github.com/jdaeman/raw.git
