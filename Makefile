CC     = gcc
CFLAGS = -Wall -Wextra -O2 -I./include -I./include/msquic
LDFLAGS = -lmsquic -lpthread
BUILD  = build
SRC    = src

all: $(BUILD) $(BUILD)/server_tcp $(BUILD)/client_tcp $(BUILD)/server_udp $(BUILD)/client_udp $(BUILD)/server_quic $(BUILD)/client_quic
	@echo "Compilare reusita!"

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/server_tcp: $(SRC)/server_tcp.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "  [OK] server_tcp"

$(BUILD)/client_tcp: $(SRC)/client_tcp.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "  [OK] client_tcp"

$(BUILD)/server_udp: $(SRC)/server_udp.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "  [OK] server_udp"

$(BUILD)/client_udp: $(SRC)/client_udp.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "  [OK] client_udp"

$(BUILD)/server_quic: $(SRC)/server_quic.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "  [OK] server_quic"

$(BUILD)/client_quic: $(SRC)/client_quic.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "  [OK] client_quic"

clean:
	rm -rf $(BUILD)
	@echo "Curatare completa."
