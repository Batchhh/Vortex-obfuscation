# VORTEX Obfuscation Framework — Makefile
#
# Targets
# ───────
#   make          — build libvortex.a and the example binary
#   make example  — build only the example
#   make lib      — build only libvortex.a
#   make clean    — remove build artefacts
#   make debug    — build with OBF_DISABLE (transparent mode, no encryption)
#
# Compiler / flags
# ────────────────
CC      ?= gcc
CFLAGS  := -std=c11 -Wall -Wextra -O2 -Iinclude \
           -fstack-protector-strong -D_FORTIFY_SOURCE=2
ARFLAGS := rcs

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    LDFLAGS_HARDEN := -Wl,-z,relro -Wl,-z,now
else
    LDFLAGS_HARDEN :=
endif
LDFLAGS_EXAMPLE := -pie $(LDFLAGS_HARDEN)

# Source files and derived object paths
SRC_DIR  := src
BUILD_DIR := build

SRCS := \
    $(SRC_DIR)/init.c     \
    $(SRC_DIR)/decrypt.c  \
    $(SRC_DIR)/utils.c    \
    $(SRC_DIR)/version.c

OBJS := $(SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

LIB     := $(BUILD_DIR)/libvortex.a
EXAMPLE := example

.PHONY: all lib example debug clean

all: lib example

lib: $(LIB)

example: $(LIB) example_usage.c
	$(CC) $(CFLAGS) -fPIE example_usage.c -L$(BUILD_DIR) -lvortex \
	    $(LDFLAGS_EXAMPLE) -o $(EXAMPLE)

debug: CFLAGS := -std=c11 -Wall -Wextra -O0 -Iinclude -DOBF_DISABLE -g \
                 -fstack-protector-strong
debug: lib
	$(CC) $(CFLAGS) -fPIE example_usage.c -L$(BUILD_DIR) -lvortex \
	    $(LDFLAGS_EXAMPLE) -o example_debug

$(LIB): $(OBJS)
	$(AR) $(ARFLAGS) $@ $^

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR) $(EXAMPLE) example_debug

# Regenerate compile_commands.json for clangd / IDE integration.
# Run 'make compdb' after adding new source files.
compdb: compile_commands.json

compile_commands.json: Makefile
	@ROOT=$$(pwd); \
	printf '[\n' > $@; \
	for f in $(SRCS); do \
	  base=$$(basename $$f .c); \
	  printf '  {\n    "directory": "'"$$ROOT"'",\n    "command": "$(CC) $(CFLAGS) -c '"$$f"' -o $(BUILD_DIR)/'"$$base"'.o",\n    "file": "'"$$f"'"\n  },\n' >> $@; \
	done; \
	printf '  {\n    "directory": "'"$$ROOT"'",\n    "command": "$(CC) $(CFLAGS) example_usage.c -L$(BUILD_DIR) -lvortex -o $(EXAMPLE)",\n    "file": "example_usage.c"\n  }\n]\n' >> $@; \
	echo "compile_commands.json updated"
