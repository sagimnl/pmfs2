-include $(PMFS2_DIR)/.config

ZM_CDEFS += CONFIG_64BIT=1
ZM_LIBS := uuid rt c
ZM_INCLUDES := $(PMFS2_DIR)
