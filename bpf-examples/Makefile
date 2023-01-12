BPF_CFLAGS ?= -Wno-visibility
BPF_TARGET ?= bpf

CLANG := clang
LLC := llc

XDP_OBJS := xsk_def_xdp_prog.o

$(XDP_OBJS): %.o: %.c $(BPF_HEADERS) $(LIBMK)
	$(CLANG) -S \
	    -target $(BPF_TARGET) \
	    -D __BPF_TRACING__ \
	    $(BPF_CFLAGS) \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Werror \
	    -O2 -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(LLC) -march=$(BPF_TARGET) -filetype=obj -o $@ ${@:.o=.ll}
