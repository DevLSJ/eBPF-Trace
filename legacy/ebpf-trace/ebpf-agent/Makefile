CLANG ?= clang
MULTIARCH := $(shell gcc -dumpmachine)

all: xdp_agent.o

xdp_agent.o: xdp_agent.c
	$(CLANG) -O2 -g -target bpf -I/usr/include/$(MULTIARCH) -c $< -o $@
