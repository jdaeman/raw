CC := gcc
SRC := raw.c
EXE := sniff

default :
	$(CC) $(SRC) -o $(EXE)

clean :
	rm $(EXE)

#git add -A
#git commit -m "file name"
#git push

#git pull

#git clone https://github.com/jdaeman/raw.git
