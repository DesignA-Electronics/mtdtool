CFLAGS = -Wall -g -pipe -O2
LFLAGS =
SOURCES=mtdtool.c mtdlib.c
OBJECTS=$(SOURCES:.c=.o)
CLANG_FORMAT?=clang-format

default: mtdtool format

%.o: %.c mtdlib.h
	$(CC) -c -o $@ $< $(CFLAGS)

mtdtool: $(OBJECTS)
	$(CC) -o $@ $(OBJECTS) $(LFLAGS)

.PHONY: clean default format

format:
	$(CLANG_FORMAT) -i $(SOURCES) mtdlib.h

clean:
	rm -rf *.o mtdtool
