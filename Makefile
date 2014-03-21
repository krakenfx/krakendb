ALL:	krakendb
LDFLAGS = -lcrypto

krakendb: krakendb.cpp db.o
db.o:	db.cpp db.h
clean:
	rm krakendb db.o