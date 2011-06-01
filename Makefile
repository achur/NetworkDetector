#
# Very simple makefile
#

# C++ compiler
CC = g++

# The CFLAGS variable sets compile flags for gcc:
#  -g                 compile with debug information
#  -Wall              give all diagnostic warnings
#  -pedantic          require compliance with ANSI standard
#  -L./libpcap-1.1.1  link the libpcap
#  -lpcap             use lpcap
CFLAGS = -Wall -g -pedantic


#  The LDFLAGS variable sets flags for linker
#  -lm    link in libm (math library)
LDFLAGS = -I./libpcap/pcap/ -I./libpcap/ -L./libpcap/ -lpcap -lm

# In this section, you list the files that are part of the project.
# If you add/change names of header/source files, here is where you
# edit the Makefile.
SOURCE = detect.cc
TARGET = detect


# The first target defined in the makefile is the one
# used when make is invoked with no argument. Given the definitions
# above, this Makefile file will build the one named TARGET and
# assume that it depends on all the named OBJECTS files.

$(TARGET) : $(SOURCE)
	$(CC) $(SOURCE) $(CFLAGS) -o $(TARGET) $(LDFLAGS)


# Phony means not a "real" target, it doesn't build anything
# The phony target "clean" that is used to remove all compiled object files.

.PHONY: clean

clean:
	@rm -fr $(TARGET) core
	