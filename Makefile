SHELL := bash
.ONESHELL:
.SHELLFLAGS := -eu -o pipefail -c
.DELETE_ON_ERROR:
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --no-builtin-rules
LIBBPF_SRC := $(abspath ./tp_src/cc/libbpf/src)

ifeq ($(origin .RECIPEPREFIX), undefined)
  $(error This Make does not support .RECIPEPREFIX. Please use GNU Make 4.0 or later)
endif
.RECIPEPREFIX = >

.PHONY:
default: src/vmlinux.h .output/libbpf.a install-headers bpf-object gen-skeleton

.PHONY: src/vmlinux.h
src/vmlinux.h:
> bin/bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/vmlinux.h

.PHONY: .output/libbpf.a
.output/libbpf.a:
> mkdir -p src/.output/libbpf/staticobjs
> $(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1            \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)	  \
		    INCLUDEDIR= LIBDIR= UAPIDIR=				  \
		    install
> ar rcs $(abspath ./src/.output/libbpf.a) $(LIBBPF_SRC)/.output/libbpf/staticobjs/*.o

.PHONY: install-headers
install-headers:
> install $(LIBBPF_SRC)/*.h -m 644 ./src/.output

.PHONY: bpf-object
bpf-object:
> clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -Isrc/.output -c src/tracememory.bpf.c -o src/.output/tracememory.bpf.o

.PHONY: gen-skeleton
gen-skeleton:
> bin/bpftool gen skeleton src/.output/tracememory.bpf.o > src/.output/tracememory.skel.h

.PHONY: clean
clean:
> rm -rf src/.output
