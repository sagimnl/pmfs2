# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

SHELL	 := /bin/bash
LIBDIR	 ?= /usr/lib/zufs
KDIR	 ?= /lib/modules/`uname -r`/build
MDIR	 ?= $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
O	 ?=

PARAMS += CONFIG_ZUFS_FS=m
PARAMS += CFLAGS_MODULE="$(CFLAGS_MODULE)"

build:
	$(MAKE) -C $(KDIR) M=$(MDIR) $(PARAMS) modules

clean:
	$(MAKE) -C $(KDIR) M=$(MDIR) clean

install: build
	$(MAKE) -C $(KDIR) M=$(MDIR) modules_install


ALL_KERNS_DIR ?= /usr/src

.PHONY: clean build install
