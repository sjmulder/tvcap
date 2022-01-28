DESTDIR?=
PREFIX?=	/usr/local

CFLAGS+=	-Wall -Wextra
LDLIBS+=	-lpcap

all: tvcap

clean:
	rm -f tvcap *.o

install: all
	install -d ${DESTDIR}${PREFIX}/bin
	install -m755 tvcap ${DESTDIR}${PREFIX}/bin/

uninstall:
	rm -f ${DESTDIR}${PREFIX}/bin/tvcap

.PHONY: all clean
