CC := gcc

SNIFF_SRC := sniff.c pktparse.c
SNIFF_EXE := sniff

ARP_SRC := arp.c util.c
ARP_EXE := arp
OPT := -lpthread

WLESS_SRC := wireless.c util.c pktparse.c
WLESS_EXE := wireless

ICMP_SRC := icmp.c util.c

SCAN_SRC := scan.c util.c

LIST := list

default : sniff arp wireless icmp scan	

sniff : $(SRC)
	$(CC) $(SNIFF_SRC) -o $(SNIFF_EXE)

arp : $(ARP_SRC)
	$(CC) $(ARP_SRC) -o $(ARP_EXE) $(OPT)

wireless : $(WLESS_SRC)
	$(CC) $(WLESS_SRC) -o $(WLESS_EXE)

icmp : $(ICMP_SRC)
	$(CC) $(ICMP_SRC) -o icmp

scan : $(SCAN_SRC)
	$(CC) $(SCAN_SRC) -o scan $(OPT)

vendor-update :
	#first, create 'list' file that has unknown mac address of vendor
	#ex) ./arp 'eth0' hostscan > sample
	#ex) ./retparse sample > list
	#second, take "make vendor-update"
	./vendor_finder.php $(subst $(LIST),,$(shell wc -w $(LIST))) < $(LIST) >> mac-vendor.txt

clean :
	rm -f $(SNIFF_EXE) $(ARP_EXE) $(WLESS_EXE) icmp scan



