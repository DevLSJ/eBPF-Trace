package main

// bpf2go: spy_supplychain.bpf.c 를 컴파일해 spy_bpfel.go + .o 를 생성·임베드한다 (docs/13 §3.2).
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel -type event spy ./bpf/spy_supplychain.bpf.c -- -I./bpf -O2 -g
