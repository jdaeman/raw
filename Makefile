CC := gcc

SNIFF_SRC := sniff.c pktparse.c
SNIFF_EXE := sniff

ARP_SRC := arp.c util.c
ARP_EXE := arp
OPT := -lpthread

WLESS_SRC := wireless.c util.c pktparse.c
WLESS_EXE := wireless

<<<<<<< HEAD
default : sniff arp wireless	

sniff : $(SNIFF_SRC)
	$(CC) $(SNIFF_SRC) -o $(SNIFF_EXE)
=======
ICMP_SRC := icmp.c util.c

LIST := list

sniff : $(SRC)
	$(CC) $(SRC) -o $(EXE)
>>>>>>> 3aa3f0463c94f89fcf0f277bec1cf0c0af920793

arp : $(ARP_SRC)
	$(CC) $(ARP_SRC) -o $(ARP_EXE) $(OPT)

wireless : $(WLESS_SRC)
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
<<<<<<< HEAD
	rm -f $(SNIFF_EXE) $(ARP_EXE) $(WLESS_EXE)
=======
	rm -f $(EXE) $(ARP_EXE) $(WLESS_EXE) icmp


#git add -A
#git commit -m "file name"
#git push
>>>>>>> 3aa3f0463c94f89fcf0f277bec1cf0c0af920793


