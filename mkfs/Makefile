# SPDX-License-Identifier: BSD-3-Clause

MKFS_MAKEFILE := $(abspath $(lastword $(MAKEFILE_LIST)))
PMFS2_MKFS_DIR := $(patsubst %/,%, $(dir $(MKFS_MAKEFILE)))
PMFS2_DIR := $(PMFS2_MKFS_DIR)/../
ZDIR ?= $(PMFS2_DIR)/../..

include $(PMFS2_DIR)/pmfs2_def.mk

ZM_NAME := mkfs.pmfs2
ZM_OBJS := mkfs.o
ZM_TYPE := ZUS_BIN
ZM_TARGET_DEPS := $(PMFS2_DIR)/libpmfs2.so
ZM_LIB_DIRS := $(PMFS2_DIR)
ZM_LIBS += pmfs2 dl

all:
	@$(MAKE) M=$(PMFS2_MKFS_DIR) -C $(ZDIR) module

clean:
	@$(MAKE) M=$(PMFS2_MKFS_DIR) -C $(ZDIR) module_clean

.PHONY: all clean
