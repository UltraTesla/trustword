CC      := gcc
CFLAGS  := -pipe -O2 -Wno-discarded-qualifiers -ggdb
LDFLAGS := -lsodium -lsqlite3 -lcrypto -lssl -largon2
OBJS    := box.o trim.o sp_parser.o read_all.o version.o hash.o strupper.o argon2_custom.o multiple_free.o
TARGET  := trustword

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) main.c $^ -o $@

.PHONY: all clean cleanall

clean:
	rm -rf *.o

cleanall: clean
	rm -rf $(TARGET)
