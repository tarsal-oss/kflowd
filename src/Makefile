#
# Makefile for kflowd
#
# Authors: Dirk Tennie <dirk@tarsal.co>
#          Barrett Lyon <blyon@tarsal.co>
#
# Copyright 2024 (c) Tarsal, Inc
#

OUTPUT := .output
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
LIBBPF_SRC := $(abspath ../libbpf/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
BINDIR := ../bin/
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
BPFTOOL ?= $(abspath ../vmlinux/$(ARCH)/bpftool)
VMLINUX := ../vmlinux/$(ARCH)/vmlinux.h
GIT_VERSION := $(shell git describe --abbrev=4 --dirty --always --tags | cut -d '-' -f 1,2,4 | sed 's/-/./1')
GLIBC_VERSION := ${shell ldd --version | head -n 1 | cut -d ')' -f2}
CLANG_VERSION := ${shell clang --version | head -n 1 | sed 's/[^0-9.]*\([0-9.]*\).*/\1/'}
LIBBPF_VERSION := ${shell git submodule status ../libbpf | cut -d ' ' -f 4 | sed 's/[v()]//g'}
DATETIME := $(shell date +'%b-%d-%Y_%H:%M:%S%z')
INCLUDES := -I$(OUTPUT) -I../libbpf/include/uapi -I$(dir $(VMLINUX))
CFLAGS := -Wextra -g -std=gnu99 -Wall -DDATETIME=\"$(DATETIME)\" -DVERSION=\"$(GIT_VERSION)\"\
          -DCLANG_VERSION=\"$(CLANG_VERSION)\" -DLIBBPF_VERSION=\"$(LIBBPF_VERSION)\"
CLANG_CHECKS := --checks=-*,clang-analyzer-*,-clang-analyzer-cplusplus* --warnings-as-errors=*
LDFLAGS := -ldl
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS)

APPS = kflowd

CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'\
		      "$(1)"\
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

define allow-override
  $(if $(or $(findstring environment,$(origin $(1))),\
            $(findstring command line,$(origin $(1)))),,\
    $(eval $(1) = $(2)))
endef

$(call allow-override,CC,$(CROSS_COMPILE)cc)
$(call allow-override,LD,$(CROSS_COMPILE)ld)

.PHONY: all
all: $(APPS)

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(BINDIR) *.deb *.rpm

.PHONY: check
check: $(APPS)
	$(call msg,CHECK, kflowd.c $(CLANG_CHECKS))
	$(Q)clang-tidy kflowd.c $(CLANG_CHECKS) -- $(CFLAGS) $(INCLUDES)

.PHONY: test
test:
	$(call msg,TEST)
	$(Q)echo | sudo ./kflowd | timeout 60 grep -m1 InfoSequenceNumber

.PHONY: ctags
ctags:
	$(call msg,CTAGS, $(shell pwd) /usr/include/ --exclude=vmlinux.h)
	$(Q)ctags -R $(shell pwd) /usr/include/ --exclude=vmlinux.h

define NFPM
name: kflowd
arch: $(PACKAGE_ARCH)
platform: linux
version: $(PACKAGE_VERSION)
provides:
- kflowd
maintainer: "Dirk Tennie <dirk@tarsal.co>"
description: |
  kflowd by Tarsal.co
  Kernel-based process monitoring for Linux via eBPF
vendor: Tarsal.co
homepage: https://www.tarsal.co
license: "GPL 2.0"
contents:
- src: ../bin/kflowd
  dst: /usr/local/bin/kflowd
- src: ../src/kflowd.service
  dst: /etc/systemd/system/kflowd.service
  type: config|noreplace
scripts:
  preinstall: ./preinstall.sh
  postinstall: ./postinstall.sh
endef
define NFPM_PRE
#!/bin/sh
echo "Stopping kflowd systemd service if running"
systemctl stop kflowd || true
endef
define NFPM_POST
#!/bin/sh
echo "\nOnly on initial installation perform the following steps:"
echo "- Configure UDP server(s) in systemd service file, e.g.
    sudo vim /etc/systemd/system/kflowd.service
      ExecStart=/usr/local/bin/kflowd -o json -v -c -u 1.2.3.4:2056,127.0.0.1:2057 -d"
    sudo systemctl daemon-reload
echo "- Enable kflowd systemd service to start automatically after reboot
    sudo systemctl enable kflowd\n"
echo "- Start kflowd systemd service and check status with the following commands:
    sudo systemctl start kflowd
    sudo systemctl status kflowd\n"
endef
export NFPM
export NFPM_PRE
export NFPM_POST

rpm deb: $(APPS)
	$(eval PACKAGE_ARCH := $(shell uname -m | if test $@ = 'deb'; then sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/'; else cat; fi))
	$(eval PACKAGE_VERSION := $(shell ../bin/kflowd --version | cut -d ' ' -f2))
	$(Q)echo "$$NFPM" > nfpm.yaml
	$(Q)echo "$$NFPM_PRE" > preinstall.sh
	$(Q)echo "$$NFPM_POST" > postinstall.sh
	$(Q)chmod 755 preinstall.sh
	$(Q)chmod 755 postinstall.sh
	$(Q)nfpm package --packager $@
	$(Q)rm *.yaml *.sh

$(OUTPUT) $(OUTPUT)/libbpf:
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# Build libbpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1\
		OBJDIR=$(dir $@)libbpf DESTDIR=$(dir $@)\
		INCLUDEDIR= LIBDIR= UAPIDIR=\
		install

# Build BPF code
$(OUTPUT)/%.bpf.o: %.bpf.c $(LIBBPF_OBJ) *.h $(VMLINUX) | $(OUTPUT)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $(filter %.c,$^) -o $@
	$(Q)$(LLVM_STRIP) -g $@ # strip useless DWARF info

# Generate BPF skeletons
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT) $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# Build user-space code
$(patsubst %,$(OUTPUT)/%.o,$(APPS)): %.o: %.skel.h

$(OUTPUT)/%.o: %.c *.h | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

# Build application binary
$(APPS): %: $(OUTPUT)/%.o $(LIBBPF_OBJ) | $(OUTPUT)
	$(Q)mkdir -p $(BINDIR)
	$(Q)$(CC) $(CFLAGS) $^ $(ALL_LDFLAGS) -lelf -lz -o $(BINDIR)$@
	$(call msg,VERSION,$(GIT_VERSION) ($(ARCH), clang $(CLANG_VERSION), glibc $(GLIBC_VERSION), libbpf $(LIBBPF_VERSION)))
	$(call msg,BINARY,$(BINDIR)$@)

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:

