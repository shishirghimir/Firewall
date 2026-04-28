# ─── FireWall — Makefile ─────────────────────────────────────────────────────
# Author: Shishir
# Usage:
#   make           → release build
#   make debug     → debug build with AddressSanitizer
#   make clean     → remove build artefacts
#   make install   → install to /usr/local/bin  (requires sudo)
#   make uninstall → remove installed binary
# ─────────────────────────────────────────────────────────────────────────────

CC      := gcc
TARGET  := firewall
SRCS    := firewall.c
HDRS    := firewall.h
OBJS    := $(SRCS:.c=.o)

# Detect pcap include/lib via pkg-config if available, otherwise fall back
PCAP_CFLAGS := $(shell pkg-config --cflags libpcap 2>/dev/null)
PCAP_LIBS   := $(shell pkg-config --libs   libpcap 2>/dev/null || echo -lpcap)

CFLAGS  := -Wall -Wextra -std=gnu11 -O2 -D_DEFAULT_SOURCE -D_GNU_SOURCE $(PCAP_CFLAGS)
LDFLAGS := $(PCAP_LIBS) -lpthread

# ── Release ──────────────────────────────────────────────────────────────────
.PHONY: all
all: $(TARGET)

$(TARGET): $(OBJS)
	@echo "  LD  $@"
	@$(CC) $(OBJS) -o $@ $(LDFLAGS)
	@echo ""
	@echo "  ✓  Build successful → ./$(TARGET)"
	@echo "     Run with: sudo ./$(TARGET) -i <interface>"

%.o: %.c $(HDRS)
	@echo "  CC  $<"
	@$(CC) $(CFLAGS) -c $< -o $@

# ── Debug (ASan + symbols) ────────────────────────────────────────────────────
.PHONY: debug
debug: CFLAGS  += -g3 -DDEBUG -fsanitize=address,undefined
debug: LDFLAGS += -fsanitize=address,undefined
debug: $(TARGET)

# ── Lint (clang-format preview) ───────────────────────────────────────────────
.PHONY: lint
lint:
	@command -v clang-format >/dev/null 2>&1 && \
	    clang-format --dry-run --Werror $(SRCS) $(HDRS) || \
	    echo "  clang-format not found, skipping"

# ── Install ───────────────────────────────────────────────────────────────────
INSTALL_DIR := /usr/local/bin
.PHONY: install
install: all
	@install -m 0755 $(TARGET) $(INSTALL_DIR)/$(TARGET)
	@echo "  ✓  Installed to $(INSTALL_DIR)/$(TARGET)"

.PHONY: uninstall
uninstall:
	@rm -f $(INSTALL_DIR)/$(TARGET)
	@echo "  ✓  Removed $(INSTALL_DIR)/$(TARGET)"

# ── Clean ─────────────────────────────────────────────────────────────────────
.PHONY: clean
clean:
	@rm -f $(OBJS) $(TARGET)
	@echo "  ✓  Cleaned"
