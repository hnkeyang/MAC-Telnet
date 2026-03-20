
CC ?= gcc
CFLAGS += -Wall -D_GNU_SOURCE -DTELNET_SUPPORT

# Run this with make LIBS=-lrt if you want to compile on kfreebsd

all: macping mndp mactelnet mactelnetd

clean: distclean

distclean:
	rm -f mactelnet macping mactelnetd mndp
	rm -f *.o

potclean:
	rm -f po/*.pot

dist: distclean potclean pot

install: all install-docs
	install -d $(DESTDIR)/usr/bin
	install mndp $(DESTDIR)/usr/bin/
	install macping $(DESTDIR)/usr/bin/
	install mactelnet $(DESTDIR)/usr/bin/
	install -d $(DESTDIR)/usr/sbin
	install -o root mactelnetd $(DESTDIR)/usr/sbin/
	install -d $(DESTDIR)/etc
	install -m 600 -o root config/mactelnetd.users $(DESTDIR)/etc/

install-strip: all install-docs
	install -d $(DESTDIR)/usr/bin
	install -s mndp $(DESTDIR)/usr/bin/
	install -s macping $(DESTDIR)/usr/bin/
	install -s mactelnet $(DESTDIR)/usr/bin/
	install -d $(DESTDIR)/usr/sbin
	install -s -o root mactelnetd $(DESTDIR)/usr/sbin/
	install -d $(DESTDIR)/etc
	install -m 600 -o root config/mactelnetd.users $(DESTDIR)/etc/

install-docs:
	install -d $(DESTDIR)/usr/share/man/man1/
	install docs/*.1 $(DESTDIR)/usr/share/man/man1/

pot: po/mactelnet.pot

po/mactelnet.pot: *.c
	xgettext --package-name=mactelnet --msgid-bugs-address=haakon.nessjoen@gmail.com -d mactelnet -C -c_ -k_ -kgettext_noop *.c -o po/mactelnet.pot

users.o: users.c users.h
	${CC} ${CFLAGS} -DUSERSFILE='"/var/etc/mactelnetd.users"' -c users.c

protocol.o: protocol.c protocol.h
	${CC} ${CFLAGS} -c protocol.c

interfaces.o: interfaces.c interfaces.h
	${CC} ${CFLAGS} -c interfaces.c

md5.o: md5.c md5.h
	${CC} ${CFLAGS} -c md5.c

mactelnet: config.h mactelnet.c mactelnet.h protocol.o console.c console.h interfaces.o users.o users.h md5.o mndp.c
	${CC} ${CFLAGS} ${LDFLAGS} -o mactelnet mactelnet.c protocol.o console.c interfaces.o users.o md5.o -DFROM_MACTELNET mndp.c ${LIBS}

mactelnetd: config.h mactelnetd.c protocol.o interfaces.o console.c console.h users.o users.h
	${CC} ${CFLAGS} ${LDFLAGS} -o mactelnetd mactelnetd.c protocol.o console.c interfaces.o users.o ${LIBS} -lubox

mndp: config.h mndp.c protocol.o interfaces.o
	${CC} ${CFLAGS} ${LDFLAGS} -o mndp mndp.c protocol.o interfaces.o ${LIBS}

macping: config.h macping.c interfaces.o protocol.o
	${CC} ${CFLAGS} ${LDFLAGS} -o macping macping.c interfaces.o protocol.o ${LIBS}
