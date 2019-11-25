CC := gcc
SRC := sniff.c pktparse.c
EXE := sniff

ARP_SRC := arp.c util.c
ARP_EXE := arp

WLESS_SRC := wireless.c util.c pktparse.c
WLESS_EXE := wireless

ICMP_SRC := icmp.c util.c

sniff : $(SRC)
	$(CC) $(SRC) -o $(EXE)

arp : $(ARP_SRC)
	$(CC) $(ARP_SRC) -o $(ARP_EXE) -lpthread

wireless : $(WLESS)
	$(CC) $(WLESS_SRC) -o $(WLESS_EXE)

icmp :
	echo Implmenting

clean :
	rm -f $(EXE) $(ARP_EXE) $(WLESS_EXE)

#git add -A
#git commit -m "file name"
#git push

#git pull

#git clone https://github.com/jdaeman/raw.git
