#
# Makefile for beaglebone capes
#

obj-$(CONFIG_CAPE_BEAGLEBONE)	+= capemgr.o

ifneq ($(CONFIG_CAPE_BEAGLEBONE),)
include $(srctree)/drivers/misc/cape/beaglebone/dts/Makefile
endif
