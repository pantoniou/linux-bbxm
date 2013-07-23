# Default C flags for am335x (ti335x)

TI_PLATFORM := ti335x

PVR_BUILD_DIR:=$(shell pwd)
DATE:=$(shell date "+%a %B %d %Z %Y" )
BUILD:=release

PVRSRV_MODNAME := pvrsrvkm

# default compiler options
ccflags-y += -fno-strict-aliasing -Wno-pointer-arith

# default build definitions
ccflags-y += \
	-DLINUX \
	-DPVR_BUILD_DIR="\"$(PVR_BUILD_DIR)\"" \
	-DPVR_BUILD_DATE="\"$(DATE)\"" \
	-DPVR_BUILD_TYPE="\"$(BUILD)\"" \
	-DPVRSRV_MODNAME="\"$(PVRSRV_MODNAME)\""

# default includes
ccflags-y += \
	-I$(src)/include4 \
	-I$(src)/services4/include \
	-I$(src)/services4/srvkm/include \
	-I$(src)/services4/srvkm/hwdefs \
	-I$(src)/services4/srvkm/bridged \
	-I$(src)/services4/srvkm/devices/sgx \
	-I$(src)/services4/srvkm/env/linux \
	-I$(src)/services4/system/include \
	-I$(src)/services4/system/$(TI_PLATFORM) \
	-I$(src)/services4/srvkm/bridged/sgx \
	-I$(src)/services4/include/env/linux

ccflags-y += \
	-DSGXCORE=530 \
	-DSGX530 \
	-DSUPPORT_SGX530 \
	-DSGX_CORE_REV=125 \
	-DSUPPORT_SGX \
	-DSUPPORT_TI_PM \
	-DPVR2D_ALT_2DHW \
	-DSYS_USING_INTERRUPTS \
	-DSUPPORT_HW_RECOVERY \
	-DSUPPORT_SGX_HWPERF \
	-DTRANSFER_QUEUE \
	-DSUPPORT_SGX_EVENT_OBJECT \
	-DPVR_SECURE_HANDLES \
	-DSUPPORT_SRVINIT \
	-DSUPPORT_PERCONTEXT_PB \
	-DDISABLE_SGX_PB_GROW_SHRINK \
	-DSUPPORT_LINUX_X86_PAT \
	-DSUPPORT_LINUX_X86_WRITECOMBINE \
	-DSUPPORT_SGX_LOW_LATENCY_SCHEDULING \
	-DSUPPORT_PVRSRV_GET_DC_SYSTEM_BUFFER \
	-DPVR_PDP_LINUX_FB \
	-DPVR_LINUX_USING_WORKQUEUES \
	-DPVR_LINUX_MISR_USING_PRIVATE_WORKQUEUE \
	-DPVR_LINUX_TIMERS_USING_WORKQUEUES \
	-DSYS_CUSTOM_POWERLOCK_WRAP \
	-DPVR_NO_FULL_CACHE_OPS \
	-DSGX_CLK_CORE_DIV5 \
	-DSUPPORT_SGX_NEW_STATUS_VALS \
	-DLDM_PLATFORM \
	\
	-I$(srctree)/arch/arm/mach-omap2

# ccflags-y += \
	-DSUPPORT_DRI_DRM \
	-DPVR_DRI_DRM_NOT_PCI \
	-DSUPPORT_DRI_DRM_NO_LIBDRM \
	-DSUPPORT_SECURE_DRM_AUTH_EXPORT \
	-DPVR_SECURE_DRM_AUTH_EXPORT \
	-DSUPPORT_XWS

# ccflags-y += \
	-DSUPPORT_DRI_DRM_PLUGIN

# ccflags-y += \
	-DSUPPORT_ACTIVE_POWER_MANAGEMENT

ccflags-y += \
	-DPVR_DRI_DRM_PLATFORM_DEV \
	-DPVR_LDM_PLATFORM_PRE_REGISTERED \
	-DPVR_LDM_PLATFORM_PRE_REGISTERED_DEV="\"$(PVRSRV_MODNAME)\"" \
	-DSYS_SGX_DEV_NAME="\"$(PVRSRV_MODNAME)\""

# ccflags-y += \
	-DSUPPORT_DRM_MODESET

ccflags-y += \
	-DDEBUG \
	-DPVRSRV_NEED_PVR_ASSERT \
	-DPVRSRV_NEED_PVR_TRACE \
	-DPVRSRV_NEED_PVR_DPF \
	-DPVR_NO_OMAP_TIMER

ccflags-y += \
	-DDEBUG_LINUX_MEMORY_ALLOCATIONS \
	-DDEBUG_LINUX_MEM_AREAS \
	-DDEBUG_LINUX_MMAP_AREAS \
	-DDEBUG_BRIDGE_KM \
	-DDEBUG_TRACE_BRIDGE_KM

obj-$(CONFIG_PVR_SGX) += pvrsrvkm.o

pvrsrvkm-y := \
	services4/srvkm/common/queue.o \
	services4/srvkm/common/hash.o \
	services4/srvkm/common/perproc.o \
	services4/srvkm/common/mem.o \
	services4/srvkm/common/power.o \
	services4/srvkm/common/deviceclass.o \
	services4/srvkm/common/metrics.o \
	services4/srvkm/common/resman.o \
	services4/srvkm/common/buffer_manager.o \
	services4/srvkm/common/pvrsrv.o \
	services4/srvkm/common/handle.o \
	services4/srvkm/common/lists.o \
	services4/srvkm/common/ra.o \
	services4/srvkm/common/devicemem.o \
	services4/srvkm/env/linux/pvr_debug.o \
	services4/srvkm/env/linux/mm.o \
	services4/srvkm/env/linux/mutex.o \
	services4/srvkm/env/linux/mmap.o \
	services4/srvkm/env/linux/module.o \
	services4/srvkm/env/linux/proc.o \
	services4/srvkm/env/linux/event.o \
	services4/srvkm/env/linux/osfunc.o \
	services4/srvkm/env/linux/pvr_bridge_k.o \
	services4/srvkm/env/linux/pdump.o \
	services4/srvkm/env/linux/mutils.o \
	services4/srvkm/env/linux/osperproc.o \
	services4/srvkm/devices/sgx/sgxtransfer.o \
	services4/srvkm/devices/sgx/sgxinit.o \
	services4/srvkm/devices/sgx/sgxutils.o \
	services4/srvkm/devices/sgx/pb.o \
	services4/srvkm/devices/sgx/sgxkick.o \
	services4/srvkm/devices/sgx/mmu.o \
	services4/srvkm/devices/sgx/sgxreset.o \
	services4/srvkm/devices/sgx/sgxpower.o \
	services4/srvkm/bridged/bridged_pvr_bridge.o \
	services4/srvkm/bridged/bridged_support.o \
	services4/srvkm/bridged/sgx/bridged_sgx_bridge.o \
	services4/system/$(TI_PLATFORM)/sysutils.o \
	services4/system/$(TI_PLATFORM)/sysconfig.o \
	\
	services4/srvkm/env/linux/pvr_drm.o

#	services4/3rdparty/dc_ti335x_linux/omaplfb_linux.o \
	services4/3rdparty/dc_ti335x_linux/omaplfb_displayclass.o

