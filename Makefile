PS5_HOST ?= ps5
PS5_PORT ?= 9021

ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
else
    $(error PS5_PAYLOAD_SDK is undefined)
endif

ELF := remoteplay_unlock_offsets.elf
SRCS := main.c patches.c self.c self-prospero.c io.c sha256.c
CFLAGS := -Wall -Wextra -Wno-sign-compare -O2 -DTESTING_BRANCH
LDLIBS := -lkernel

all: $(ELF)

$(ELF): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDLIBS)

clean:
	rm -f $(ELF)

test: $(ELF)
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $<

.PHONY: all clean test
