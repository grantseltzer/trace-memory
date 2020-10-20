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

src/vmlinux.h:
> bin/bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/vmlinux.h

.output/libbpf.a:
> mkdir -p src/.output/libbpf/staticobjs
> $(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1            \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)	  \
		    INCLUDEDIR= LIBDIR= UAPIDIR=				  \
		    install
> ar rcs $(abspath ./bin/libbpf.a) ./src/.output/libbpf/staticobjs/*.o

clean:
> rm bin/*
> rm src/.output/*