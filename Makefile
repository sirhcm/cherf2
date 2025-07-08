ifeq (,$(wildcard config.mk))
	$(error "config.mk not found. run ./configure first")
endif

include config.mk

SRCS := $(wildcard *.c)
OBJS := $(SRCS:.c=.o)
CFLAGS := -Wall -Werror -Wno-incompatible-pointer-types -std=c99 -g -fsanitize=address \
          $(MONOCYPHER_CFLAGS) $(BRAID_CFLAGS)
LDFLAGS := $(MONOCYPHER_LDFLAGS) $(BRAID_LDFLAGS) -fsanitize=address

.PHONY: all clean
all: cherf

cherf: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

$(OBJS): %.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) cherf

