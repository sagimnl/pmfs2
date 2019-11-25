# SPDX-License-Identifier: GPL-2.0

PMFS2_MAKEFILE := $(abspath $(lastword $(MAKEFILE_LIST)))
PMFS2_DIR := $(patsubst %/,%, $(dir $(PMFS2_MAKEFILE)))
ZDIR ?= $(PMFS2_DIR)/../..
MAKEFLAGS := --no-print-directory
-include $(ZDIR)/.config
include $(PMFS2_DIR)/pmfs2_def.mk

ZM_NAME := pmfs2
ZM_OBJS := kinu.o inode.o balloc.o btree.o super.o dir.o symlink.o rw.o
ZM_OBJS += xattr.o recon.o pmus.o
ZM_OBJS_DEPS += $(PMFS2_DIR)/pmfs2_def.mk
#ZM_CDEFS :=
ZM_POST_BUILD := mkfs
ZM_POST_CLEAN := clean_mkfs

all:
	@$(MAKE) M=$(PMFS2_DIR) -C $(ZDIR) module

clean:
	@$(MAKE) M=$(PMFS2_DIR) -C $(ZDIR) module_clean

mkfs:
	@$(MAKE) M=$(PMFS2_DIR)/mkfs -C $(ZDIR) module

clean_mkfs:
	@$(MAKE) M=$(PMFS2_DIR)/mkfs -C $(ZDIR) module_clean

.PHONY: all clean mkfs clean_mkfs

