obj-m += sct_monitor.o

# common/ sits two levels up from this directory when built via M=
ccflags-y := -I$(M)/../../common
# If your distro kbuild dislikes $(M) in ccflags, copy common/baseline.h
# here and drop this line (keep the two copies in sync).
