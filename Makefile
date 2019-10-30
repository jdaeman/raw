CC := gcc
SRC := sniff.c pktparse.c
EXE := sniff

ARP_SRC := arp.c
ARP_EXE := arp

sniff : $(SRC)
	$(CC) $(SRC) -o $(EXE)

arp : $(ARP_SRC)
	$(CC) $(ARP_SRC) -o $(ARP_EXE)

clean :
	rm -f $(EXE) $(ARP_EXE)

#git add -A
#git commit -m "file name"
#git push

#git pull

#git clone https://github.com/jdaeman/raw.git
