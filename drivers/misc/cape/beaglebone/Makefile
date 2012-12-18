#
# Makefile for beaglebone capes
#

obj-$(CONFIG_CAPE_BEAGLEBONE)		+= capemgr.o
obj-$(CONFIG_CAPE_BEAGLEBONE_GEIGER)	+= cape-bone-geiger.o

ifneq ($(CONFIG_CAPE_BEAGLEBONE),)
include $(srctree)/drivers/misc/cape/beaglebone/dts/Makefile
endif
