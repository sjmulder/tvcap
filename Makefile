CFLAGS+=	-Wall -Wextra
LDLIBS+=	-lpcap

all: tvcap

clean:
	rm -f tvcap *.o

.PHONY: all clean
