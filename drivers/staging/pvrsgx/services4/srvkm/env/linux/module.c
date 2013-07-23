/*************************************************************************/ /*!
@Title          Linux module setup
@Copyright      Copyright (c) Imagination Technologies Ltd. All Rights Reserved
@License        Dual MIT/GPLv2

The contents of this file are subject to the MIT license as set out below.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

Alternatively, the contents of this file may be used under the terms of
the GNU General Public License Version 2 ("GPL") in which case the provisions
of GPL are applicable instead of those above.

If you wish to allow use of your version of this file only under the terms of
GPL, and not to allow others to use your version of this file under the terms
of the MIT license, indicate your decision by deleting the provisions above
and replace them with the notice and other provisions required by GPL as set
out in the file called "GPL-COPYING" included in this distribution. If you do
not delete the provisions above, a recipient may use your version of this file
under the terms of either the MIT license or GPL.

This License is also included in this distribution in the file called
"MIT-COPYING".

EXCEPT AS OTHERWISE STATED IN A NEGOTIATED AGREEMENT: (A) THE SOFTWARE IS
PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE AND NONINFRINGEMENT; AND (B) IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/ /**************************************************************************/

#include <linux/version.h>

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/platform_device.h>
#include <linux/device.h>
#include <asm/uaccess.h>
#include <linux/of.h>
#include <linux/of_platform.h>

#include "img_defs.h"
#include "services.h"
#include "kerneldisplay.h"
#include "kernelbuffer.h"
#include "syscommon.h"
#include "pvrmmap.h"
#include "mutils.h"
#include "mm.h"
#include "mmap.h"
#include "mutex.h"
#include "pvr_debug.h"
#include "srvkm.h"
#include "perproc.h"
#include "handle.h"
#include "pvr_bridge_km.h"
#include "proc.h"
#include "pvrmodule.h"
#include "private_data.h"
#include "lock.h"
#include "linkage.h"
#include "buffer_manager.h"

#if defined(PVR_ANDROID_NATIVE_WINDOW_HAS_SYNC)
#include "pvr_sync.h"
#endif

#define DRVNAME		PVRSRV_MODNAME
#define DEVNAME		PVRSRV_MODNAME

#define PRIVATE_DATA(pFile) ((pFile)->private_data)

/*
 * This is all module configuration stuff required by the linux kernel.
 */
MODULE_SUPPORTED_DEVICE(DEVNAME);

#if defined(PVRSRV_NEED_PVR_DPF)
#include <linux/moduleparam.h>
extern IMG_UINT32 gPVRDebugLevel;
module_param(gPVRDebugLevel, uint, 0644);
MODULE_PARM_DESC(gPVRDebugLevel, "Sets the level of debug output (default 0x7)");
#endif /* defined(PVRSRV_NEED_PVR_DPF) */

/* PRQA S 3207 2 */ /* ignore 'not used' warning */
EXPORT_SYMBOL(PVRGetDisplayClassJTable);
EXPORT_SYMBOL(PVRGetBufferClassJTable);

#if defined(PVR_LDM_DEVICE_CLASS)
/*
 * Device class used for /sys entries (and udev device node creation)
 */
static struct class *psPvrClass;
#endif

/*
 * This is the major number we use for all nodes in /dev.
 */
static int AssignedMajorNumber;

/*
 * These are the operations that will be associated with the device node
 * we create.
 *
 * With gcc -W, specifying only the non-null members produces "missing
 * initializer" warnings.
*/
static int PVRSRVOpen(struct inode* pInode, struct file* pFile);
static int PVRSRVRelease(struct inode* pInode, struct file* pFile);

static struct file_operations pvrsrv_fops =
{
	.owner=THIS_MODULE,
	.unlocked_ioctl = PVRSRV_BridgeDispatchKM,
	.open=PVRSRVOpen,
	.release=PVRSRVRelease,
	.mmap=PVRMMap,
};

PVRSRV_LINUX_MUTEX gPVRSRVLock;

/* PID of process being released */
IMG_UINT32 gui32ReleasePID;

#if defined(DEBUG) && defined(PVR_MANUAL_POWER_CONTROL)
static IMG_UINT32 gPVRPowerLevel;
#endif

/*
 * This is the driver interface we support.  
 */
static int PVRSRVDriverRemove(struct platform_device *device);
static int PVRSRVDriverProbe(struct platform_device *device);
static int PVRSRVDriverSuspend(struct platform_device *device, pm_message_t state);
static void PVRSRVDriverShutdown(struct platform_device *device);
static int PVRSRVDriverResume(struct platform_device *device);

#if defined(CONFIG_OF)
static const struct of_device_id powervr_of_match[] = {
	{ .compatible = DRVNAME },
	{},
};
MODULE_DEVICE_TABLE(of, powervr_of_match);
#endif

static struct platform_driver powervr_driver = {
	.driver = {
		.name		= DRVNAME,
		.of_match_table = of_match_ptr(powervr_of_match),
	},
	.probe		= PVRSRVDriverProbe,
	.remove		= PVRSRVDriverRemove,
	.suspend	= PVRSRVDriverSuspend,
	.resume		= PVRSRVDriverResume,
	.shutdown	= PVRSRVDriverShutdown,
};

struct platform_device *gpsPVRLDMDev;

/*!
******************************************************************************

 @Function		PVRSRVDriverProbe

 @Description

 See whether a given device is really one we can drive.  The platform bus
 handler has already established that we should be able to service this device
 because of the name match.  We probably don't need to do anything else.

 @input pDevice - the device for which a probe is requested

 @Return 0 for success or <0 for an error.

*****************************************************************************/
static int PVRSRVDriverProbe(struct platform_device *pDevice)
{
	SYS_DATA *psSysData;

	pr_info("%s\n", __func__);

	PVR_TRACE(("PVRSRVDriverProbe(pDevice=%p)", pDevice));

#if 0   /* INTEGRATION_POINT */
	/* Some systems require device-specific system initialisation.
	 * E.g. this lets the OS track a device's dependencies on various
	 * system hardware.
	 *
	 * Note: some systems use this to enable HW that SysAcquireData
	 * will depend on, therefore it must be called first.
	 */
	if (PerDeviceSysInitialise((IMG_PVOID)pDevice) != PVRSRV_OK)
	{
		return -EINVAL;
	}
#endif	
	/* SysInitialise only designed to be called once.
	 */
	psSysData = SysAcquireDataNoCheck();
	if (psSysData == IMG_NULL)
	{
		gpsPVRLDMDev = pDevice;
		if (SysInitialise() != PVRSRV_OK)
		{
			return -ENODEV;
		}
	}

	return 0;
}


/*!
******************************************************************************

 @Function		PVRSRVDriverRemove

 @Description

 This call is the opposite of the probe call: it is called when the device is
 being removed from the driver's control.  See the file $KERNELDIR/drivers/
 base/bus.c:device_release_driver() for the call to this function.

 This is the correct place to clean up anything our driver did while it was
 asoociated with the device.

 @input pDevice - the device for which driver detachment is happening

 @Return 0 for success or <0 for an error.

*****************************************************************************/
static int PVRSRVDriverRemove(struct platform_device *pDevice)
{
	SYS_DATA *psSysData;

	pr_info("%s\n", __func__);

	PVR_TRACE(("PVRSRVDriverRemove(pDevice=%p)", pDevice));

	SysAcquireData(&psSysData);
	
#if defined(DEBUG) && defined(PVR_MANUAL_POWER_CONTROL)
	if (gPVRPowerLevel != 0)
	{
		if (PVRSRVSetPowerStateKM(PVRSRV_SYS_POWER_STATE_D0) == PVRSRV_OK)
		{
			gPVRPowerLevel = 0;
		}
	}
#endif
	(void) SysDeinitialise(psSysData);

	gpsPVRLDMDev = IMG_NULL;

#if 0   /* INTEGRATION_POINT */
	/* See previous integration point for details. */
	if (PerDeviceSysDeInitialise((IMG_PVOID)pDevice) != PVRSRV_OK)
	{
		return -EINVAL;
	}
#endif
	return 0;
}

static PVRSRV_LINUX_MUTEX gsPMMutex;
static IMG_BOOL bDriverIsSuspended;
static IMG_BOOL bDriverIsShutdown;

/*!
******************************************************************************

 @Function		PVRSRVDriverShutdown

 @Description

 Suspend device operation for system shutdown.  This is called as part of the
 system halt/reboot process.  The driver is put into a quiescent state by 
 setting the power state to D3.

 @input pDevice - the device for which shutdown is requested

 @Return nothing

*****************************************************************************/
static void PVRSRVDriverShutdown(struct platform_device *pDevice)
{
	PVR_TRACE(("PVRSRVDriverShutdown(pDevice=%p)", pDevice));

	LinuxLockMutex(&gsPMMutex);

	if (!bDriverIsShutdown && !bDriverIsSuspended)
	{
		/*
		 * Take the bridge mutex, and never release it, to stop
		 * processes trying to use the driver after it has been
		 * shutdown.
		 */
		LinuxLockMutexNested(&gPVRSRVLock, PVRSRV_LOCK_CLASS_BRIDGE);

		(void) PVRSRVSetPowerStateKM(PVRSRV_SYS_POWER_STATE_D3);
	}

	bDriverIsShutdown = IMG_TRUE;

	/* The bridge mutex is held on exit */
	LinuxUnLockMutex(&gsPMMutex);
}

/*!
******************************************************************************

 @Function		PVRSRVDriverSuspend

 @Description

 For 2.6 kernels:
 Suspend device operation.  We always get three calls to this regardless of
 the state (D1-D3) chosen.  The order is SUSPEND_DISABLE, SUSPEND_SAVE_STATE
 then SUSPEND_POWER_DOWN.  We take action as soon as we get the disable call,
 the other states not being handled by us yet.

 For MontaVista 2.4 kernels:
 This call gets made once only when someone does something like

	# echo -e -n "suspend powerdown 0" >/sys.devices/legacy/pvrsrv0/power

 The 3rd, numeric parameter (0) in the above has no relevence and is not
 passed into us.  The state parameter is always zero and the level parameter
 is always SUSPEND_POWER_DOWN.  Vive la difference!

 @input pDevice - the device for which resume is requested

 @Return 0 for success or <0 for an error.

*****************************************************************************/
static int PVRSRVDriverSuspend(struct platform_device *pDevice, pm_message_t state)
{
	int res = 0;
#if !(defined(DEBUG) && defined(PVR_MANUAL_POWER_CONTROL))
	PVR_TRACE(( "PVRSRVDriverSuspend(pDevice=%p)", pDevice));

	LinuxLockMutex(&gsPMMutex);

	if (!bDriverIsSuspended && !bDriverIsShutdown)
	{
		LinuxLockMutexNested(&gPVRSRVLock, PVRSRV_LOCK_CLASS_BRIDGE);

		if (PVRSRVSetPowerStateKM(PVRSRV_SYS_POWER_STATE_D3) == PVRSRV_OK)
		{
			/* The bridge mutex will be held until we resume */
			bDriverIsSuspended = IMG_TRUE;
		}
		else
		{
			LinuxUnLockMutex(&gPVRSRVLock);
			res = -EINVAL;
		}
	}

	LinuxUnLockMutex(&gsPMMutex);
#endif
	return res;
}


/*!
******************************************************************************

 @Function		PVRSRVDriverResume

 @Description

 Resume device operation following a lull due to earlier suspension.  It is
 implicit we're returning to D0 (fully operational) state.  We always get three
 calls to this using level thus: RESUME_POWER_ON, RESUME_RESTORE_STATE then
 RESUME_ENABLE.  On 2.6 kernels We don't do anything until we get the enable
 call; on the MontaVista set-up we only ever get the RESUME_POWER_ON call.

 @input pDevice - the device for which resume is requested

 @Return 0 for success or <0 for an error.

*****************************************************************************/
static int PVRSRVDriverResume(struct platform_device *pDevice)
{
	int res = 0;
#if !(defined(DEBUG) && defined(PVR_MANUAL_POWER_CONTROL))
	PVR_TRACE(("PVRSRVDriverResume(pDevice=%p)", pDevice));

	LinuxLockMutex(&gsPMMutex);

	if (bDriverIsSuspended && !bDriverIsShutdown)
	{
		if (PVRSRVSetPowerStateKM(PVRSRV_SYS_POWER_STATE_D0) == PVRSRV_OK)
		{
			bDriverIsSuspended = IMG_FALSE;
			LinuxUnLockMutex(&gPVRSRVLock);
		}
		else
		{
			/* The bridge mutex is not released on failure */
			res = -EINVAL;
		}
	}

	LinuxUnLockMutex(&gsPMMutex);
#endif
	return res;
}


/*!
******************************************************************************

 @Function		PVRSRVOpen

 @Description

 Release access the PVR services node - called when a file is closed, whether
 at exit or using close(2) system call.

 @input pInode - the inode for the file being openeded

 @input pFile - the file handle data for the actual file being opened

 @Return 0 for success or <0 for an error.

*****************************************************************************/
static int PVRSRVOpen(struct inode unref__ * pInode, struct file *pFile)
{
	PVRSRV_FILE_PRIVATE_DATA *psPrivateData;
	IMG_HANDLE hBlockAlloc;
	int iRet = -ENOMEM;
	PVRSRV_ERROR eError;
	IMG_UINT32 ui32PID;

	LinuxLockMutexNested(&gPVRSRVLock, PVRSRV_LOCK_CLASS_BRIDGE);

	ui32PID = OSGetCurrentProcessIDKM();

	if (PVRSRVProcessConnect(ui32PID, 0) != PVRSRV_OK)
		goto err_unlock;

	eError = OSAllocMem(PVRSRV_OS_NON_PAGEABLE_HEAP,
						sizeof(PVRSRV_FILE_PRIVATE_DATA),
						(IMG_PVOID *)&psPrivateData,
						&hBlockAlloc,
						"File Private Data");

	if(eError != PVRSRV_OK)
		goto err_unlock;

	psPrivateData->hKernelMemInfo = NULL;
	psPrivateData->ui32OpenPID = ui32PID;
	psPrivateData->hBlockAlloc = hBlockAlloc;
	PRIVATE_DATA(pFile) = psPrivateData;
	iRet = 0;
err_unlock:	
	LinuxUnLockMutex(&gPVRSRVLock);
	return iRet;
}


/*!
******************************************************************************

 @Function		PVRSRVRelease

 @Description

 Release access the PVR services node - called when a file is closed, whether
 at exit or using close(2) system call.

 @input pInode - the inode for the file being released

 @input pFile - the file handle data for the actual file being released

 @Return 0 for success or <0 for an error.

*****************************************************************************/
static int PVRSRVRelease(struct inode unref__ * pInode, struct file *pFile)
{
	PVRSRV_FILE_PRIVATE_DATA *psPrivateData;
	int err = 0;

	LinuxLockMutexNested(&gPVRSRVLock, PVRSRV_LOCK_CLASS_BRIDGE);

	psPrivateData = PRIVATE_DATA(pFile);
	if (psPrivateData != IMG_NULL)
	{
		if(psPrivateData->hKernelMemInfo)
		{
			PVRSRV_KERNEL_MEM_INFO *psKernelMemInfo;

			/* Look up the meminfo we just exported */
			if(PVRSRVLookupHandle(KERNEL_HANDLE_BASE,
								  (IMG_PVOID *)&psKernelMemInfo,
								  psPrivateData->hKernelMemInfo,
								  PVRSRV_HANDLE_TYPE_MEM_INFO) != PVRSRV_OK)
			{
				PVR_DPF((PVR_DBG_ERROR, "%s: Failed to look up export handle", __FUNCTION__));
				err = -EFAULT;
				goto err_unlock;
			}

			/* Tell the XProc about the export if required */
			if (psKernelMemInfo->sShareMemWorkaround.bInUse)
			{
				BM_XProcIndexRelease(psKernelMemInfo->sShareMemWorkaround.ui32ShareIndex);
			}

			/* This drops the psMemInfo refcount bumped on export */
			if(FreeMemCallBackCommon(psKernelMemInfo, 0,
									 PVRSRV_FREE_CALLBACK_ORIGIN_EXTERNAL) != PVRSRV_OK)
			{
				PVR_DPF((PVR_DBG_ERROR, "%s: FreeMemCallBackCommon failed", __FUNCTION__));
				err = -EFAULT;
				goto err_unlock;
			}
		}

		/* Usually this is the same as OSGetCurrentProcessIDKM(),
		 * but not necessarily (e.g. fork(), child closes last..)
		 */
		gui32ReleasePID = psPrivateData->ui32OpenPID;
		PVRSRVProcessDisconnect(psPrivateData->ui32OpenPID);
		gui32ReleasePID = 0;

		OSFreeMem(PVRSRV_OS_NON_PAGEABLE_HEAP,
				  sizeof(PVRSRV_FILE_PRIVATE_DATA),
				  psPrivateData, psPrivateData->hBlockAlloc);

		PRIVATE_DATA(pFile) = IMG_NULL; /*nulling shared pointer*/
	}

err_unlock:
	LinuxUnLockMutex(&gPVRSRVLock);
	return err;
}


/*!
******************************************************************************

 @Function		PVRCore_Init

 @Description

 Insert the driver into the kernel.

 The device major number is allocated by the kernel dynamically.  This means
 that the device node (nominally /dev/pvrsrv) will need to be re-made at boot
 time if the number changes between subsequent loads of the module.  While the
 number often stays constant between loads this is not guaranteed.  The node
 is made as root on the shell with:

 		mknod /dev/pvrsrv c nnn 0

 where nnn is the major number found in /proc/devices for DEVNAME and also
 reported by the PVR_DPF() - look at the boot log using dmesg' to see this).

 Currently the auto-generated script /etc/init.d/rc.pvr handles creation of
 the device.  In other environments the device may be created either through
 devfs or sysfs.

 Readable proc-filesystem entries under /proc/pvr are created with
 CreateProcEntries().  These can be read at runtime to get information about
 the device (eg. 'cat /proc/pvr/vm')

 __init places the function in a special memory section that the kernel frees
 once the function has been run.  Refer also to module_init() macro call below.

 @input none

 @Return none

*****************************************************************************/
static int PVRCore_Init(void)
{
	int error;
#if defined(PVR_LDM_DEVICE_CLASS)
	struct device *psDev;
#endif

	pr_info("%s\n", __func__);

	/*
	 * Must come before attempting to print anything via Services.
	 * For DRM, the initialisation will already have been done.
	 */
	PVRDPFInit();
	PVR_TRACE(("PVRCore_Init"));

	LinuxInitMutex(&gsPMMutex);
	LinuxInitMutex(&gPVRSRVLock);

	if (CreateProcEntries())
	{
		error = -ENOMEM;
		return error;
	}

	if (PVROSFuncInit() != PVRSRV_OK)
	{
		error = -ENOMEM;
		goto init_failed;
	}

	PVRLinuxMUtilsInit();

	if(LinuxMMInit() != PVRSRV_OK)
	{
		error = -ENOMEM;
		goto init_failed;
	}

	LinuxBridgeInit();
	

	PVRMMapInit();

	if ((error = platform_driver_register(&powervr_driver)) != 0)
	{
		PVR_DPF((PVR_DBG_ERROR, "PVRCore_Init: unable to register platform driver (%d)", error));

		goto init_failed;
	}

	AssignedMajorNumber = register_chrdev(0, DEVNAME, &pvrsrv_fops);

	if (AssignedMajorNumber <= 0)
	{
		PVR_DPF((PVR_DBG_ERROR, "PVRCore_Init: unable to get major number"));

		error = -EBUSY;
		goto sys_deinit;
	}

	PVR_TRACE(("PVRCore_Init: major device %d", AssignedMajorNumber));

#if defined(PVR_LDM_DEVICE_CLASS)
	/*
	 * This code (using GPL symbols) facilitates automatic device
	 * node creation on platforms with udev (or similar).
	 */
	psPvrClass = class_create(THIS_MODULE, "pvr");

	if (IS_ERR(psPvrClass))
	{
		PVR_DPF((PVR_DBG_ERROR, "PVRCore_Init: unable to create class (%ld)", PTR_ERR(psPvrClass)));
		error = -EBUSY;
		goto unregister_device;
	}

	psDev = device_create(psPvrClass, NULL, MKDEV(AssignedMajorNumber, 0),
				  NULL,
				  DEVNAME);
	if (IS_ERR(psDev))
	{
		PVR_DPF((PVR_DBG_ERROR, "PVRCore_Init: unable to create device (%ld)", PTR_ERR(psDev)));
		error = -EBUSY;
		goto destroy_class;
	}
#endif /* defined(PVR_LDM_DEVICE_CLASS) */

#if defined(PVR_ANDROID_NATIVE_WINDOW_HAS_SYNC)
	PVRSyncDeviceInit();
#endif
	return 0;

#if defined(PVR_LDM_DEVICE_CLASS)
destroy_class:
	class_destroy(psPvrClass);
unregister_device:
	unregister_chrdev((IMG_UINT)AssignedMajorNumber, DEVNAME);
#endif
sys_deinit:

	platform_driver_unregister(&powervr_driver);

init_failed:
	PVRMMapCleanup();
	LinuxMMCleanup();
	LinuxBridgeDeInit();
	PVROSFuncDeInit();
	RemoveProcEntries();

	return error;

} /*PVRCore_Init*/


/*!
*****************************************************************************

 @Function		PVRCore_Cleanup

 @Description	

 Remove the driver from the kernel.

 There's no way we can get out of being unloaded other than panicking; we
 just do everything and plough on regardless of error.

 __exit places the function in a special memory section that the kernel frees
 once the function has been run.  Refer also to module_exit() macro call below.

 Note that the for LDM on MontaVista kernels, the positioning of the driver
 de-registration is the opposite way around than would be suggested by the
 registration case or the 2,6 kernel case.  This is the correct way to do it
 and the kernel panics if you change it.  You have been warned.

 @input none

 @Return none

*****************************************************************************/
static void PVRCore_Cleanup(void)
{
	PVR_TRACE(("PVRCore_Cleanup"));

#if defined(PVR_ANDROID_NATIVE_WINDOW_HAS_SYNC)
	PVRSyncDeviceDeInit();
#endif

#if defined(PVR_LDM_DEVICE_CLASS)
	device_destroy(psPvrClass, MKDEV(AssignedMajorNumber, 0));
	class_destroy(psPvrClass);
#endif

	unregister_chrdev((IMG_UINT)AssignedMajorNumber, DEVNAME);

	platform_driver_unregister(&powervr_driver);

	PVRMMapCleanup();

	LinuxMMCleanup();

	LinuxBridgeDeInit();

	PVROSFuncDeInit();

	RemoveProcEntries();

	PVR_TRACE(("PVRCore_Cleanup: unloading"));
}

/*
 * These macro calls define the initialisation and removal functions of the
 * driver.  Although they are prefixed `module_', they apply when compiling
 * statically as well; in both cases they define the function the kernel will
 * run to start/stop the driver.
*/
module_init(PVRCore_Init);
module_exit(PVRCore_Cleanup);
