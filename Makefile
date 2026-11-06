CC ?= cc
CPPFLAGS += -D_DEFAULT_SOURCE -Isrc
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic -Werror
LDLIBS += -lssl -lcrypto

.PHONY: all test integration clean
all: build/aegis-inline

build:
	mkdir -p $@

build/aegis-inline: src/main.c src/session.c src/packet.c src/session.h src/packet.h | build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(filter %.c,$^) $(LDLIBS) -o $@

build/test-packet: tests/test_packet.c src/packet.c src/packet.h | build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(filter %.c,$^) $(LDLIBS) -o $@

build/test-session: tests/test_session.c src/session.c src/session.h src/packet.h | build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(filter %.c,$^) $(LDLIBS) -o $@

test: all build/test-packet build/test-session
	./build/test-packet
	./tests/session.sh

integration: all
	./tests/integration.sh

clean:
	rm -rf build
