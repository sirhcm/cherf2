ifeq (,$(wildcard config.mk))
	$(error "config.mk not found. run ./configure first")
endif

include config.mk

SRCS := $(wildcard *.c)
OBJS := $(SRCS:.c=.o)
CFLAGS := -Wall -Werror -Wno-incompatible-pointer-types \
          -std=c99 -g -D_POSIX_C_SOURCE=200112L \
          -O2 \
          $(MONOCYPHER_CFLAGS) $(BRAID_CFLAGS)
LDFLAGS := $(MONOCYPHER_LDFLAGS) $(BRAID_LDFLAGS)

.PHONY: all clean
all: cherf2

cherf2: $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

$(OBJS): %.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) cherf2

