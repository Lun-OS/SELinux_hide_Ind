ifndef TARGET_COMPILE
    $(error TARGET_COMPILE not set)
endif

KP_DIR ?= ../KernelPatch

CC = $(TARGET_COMPILE)gcc
LD = $(TARGET_COMPILE)ld

CFLAGS += -nostdinc
CFLAGS += -fno-pic -fno-PIC -fno-pie -fno-stack-protector
CFLAGS += -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-exceptions

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include
INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))
INCLUDE_FLAGS += -I$(KP_DIR)/kernel/linux

objs := sehide_main.o se_util.o se_symbol.o se_layout.o se_policydb.o se_rules.o se_render.o se_gate.o se_bprm.o se_recal.o se_shadow.o se_status.o

all: SELinux_hide_From_LunSU.kpm

SELinux_hide_From_LunSU.kpm: ${objs}
	${CC} -r -o $@ $^

%.o: %.c
	${CC} $(CFLAGS) $(INCLUDE_FLAGS) -TSELinux_hide_From_LunSU.lds -c -O2 -o $@ $<

.PHONY: clean
clean:
	rm -rf *.kpm *.o
