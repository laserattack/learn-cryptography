PROGRAM_NAME    = test.out
SOURCES         = test.c
OBJECTS         = $(SOURCES:.c=.o)
PROGRAM_BIN     = $(PROGRAM_NAME)

CC              = cc
CFLAGS          = -Wall -Wextra -std=c99
LDFLAGS         = 
LIBS            = 

all: $(PROGRAM_BIN)

$(PROGRAM_BIN): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $(PROGRAM_BIN) $(OBJECTS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(PROGRAM_BIN) $(OBJECTS)

.PHONY: all clean
