CC = gcc
CFLAGS = -Wall -Wextra -O2 $(shell pkg-config --cflags libmodbus libcjson)
LIBS = $(shell pkg-config --libs libmodbus libcjson)

BIN_DIR = bin
LOG_DIR = logs

# Arquivos fonte
SRC_ATTACKER = src/attacker.c
SRC_CONTROLLER = src/controller.c

# Binários que serão gerados
BIN_ATTACKER = $(BIN_DIR)/attacker
BIN_CONTROLLER = $(BIN_DIR)/controller

.PHONY: all clean

all: $(BIN_ATTACKER) $(BIN_CONTROLLER)

$(BIN_ATTACKER): $(SRC_ATTACKER) | $(BIN_DIR) $(LOG_DIR)
	$(CC) $(CFLAGS) $< -o $@ $(LIBS)

$(BIN_CONTROLLER): $(SRC_CONTROLLER) | $(BIN_DIR) $(LOG_DIR)
	$(CC) $(CFLAGS) $< -o $@ $(LIBS)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(LOG_DIR):
	mkdir -p $(LOG_DIR)

clean:
	rm -f $(BIN_ATTACKER) $(BIN_CONTROLLER)
