LDLIBS=-lpcap -lpthread

all: airodump

airodump: main.o mac.o radiotap.o beaconframe.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f airodump *.o
