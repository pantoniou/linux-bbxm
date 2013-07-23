/*************************************************************************/ /*!
@Title          PowerVR drm driver
@Copyright      Copyright (c) Imagination Technologies Ltd. All Rights Reserved
@Description    linux module setup
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
#if defined(SUPPORT_DRI_DRM)

#include <linux/version.h>

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <asm/ioctl.h>
#include <drm/drmP.h>
#include <drm/drm.h>
#include <linux/of.h>
#include <linux/of_platform.h>

#include "img_defs.h"
#include "services.h"
#include "kerneldisplay.h"
#include "kernelbuffer.h"
#include "syscommon.h"
#include "pvrmmap.h"
#include "mm.h"
#include "mmap.h"
#include "mutex.h"
#include "pvr_debug.h"
#include "srvkm.h"
#include "perproc.h"
#include "handle.h"
#include "pvr_bridge_km.h"
#include "pvr_bridge.h"
#include "proc.h"
#include "pvrmodule.h"
#include "pvrversion.h"
#include "lock.h"
#include "linkage.h"
#include "pvr_drm.h"

#define PVR_DRM_NAME	PVRSRV_MODNAME
#define PVR_DRM_DESC	"Imagination Technologies PVR DRM"
#define	PVR_DRM_DATE	"20110701"

DECLARE_WAIT_QUEUE_HEAD(sWaitForInit);

/* Once bInitComplete and bInitFailed are set, they stay set */
IMG_BOOL bInitComplete;
IMG_BOOL bInitFailed;

struct platform_device *gpsPVRLDMDev;

struct drm_device *gpsPVRDRMDev;

#define PVR_DRM_FILE struct drm_file *

#if !defined(SUPPORT_DRI_DRM_EXT) && !defined(SUPPORT_DRI_DRM_PLUGIN)
#if defined(PVR_LDM_PLATFORM_PRE_REGISTERED)
static struct platform_device_id asPlatIdList[] = {
	{SYS_SGX_DEV_NAME, 0},
	{}
};
#endif
#endif	/* !defined(SUPPORT_DRI_DRM_EXT) */

DRI_DRM_STATIC int
PVRSRVDrmLoad(struct drm_device *dev, unsigned long flags)
{
	int iRes = 0;

	PVR_TRACE(("PVRSRVDrmLoad"));

	gpsPVRDRMDev = dev;
#if !defined(SUPPORT_DRI_DRM_PLUGIN)
	gpsPVRLDMDev = dev->platformdev;
#endif

#if defined(PDUMP)
	iRes = dbgdrv_init();
	if (iRes != 0)
	{
		goto exit;
	}
#endif
	/* Module initialisation */
	iRes = PVRCore_Init();
	if (iRes != 0)
	{
		goto exit_dbgdrv_cleanup;
	}

#if defined(DISPLAY_CONTROLLER)
	iRes = PVR_DRM_MAKENAME(DISPLAY_CONTROLLER, _Init)(dev);
	if (iRes != 0)
	{
		goto exit_pvrcore_cleanup;
	}
#endif
	goto exit;

#if defined(DISPLAY_CONTROLLER)
exit_pvrcore_cleanup:
	PVRCore_Cleanup();
#endif
exit_dbgdrv_cleanup:
#if defined(PDUMP)
	dbgdrv_cleanup();
#endif
exit:
	if (iRes != 0)
	{
		bInitFailed = IMG_TRUE;
	}
	bInitComplete = IMG_TRUE;

	wake_up_interruptible(&sWaitForInit);

	return iRes;
}

DRI_DRM_STATIC int
PVRSRVDrmUnload(struct drm_device *dev)
{
	PVR_TRACE(("PVRSRVDrmUnload"));

#if defined(DISPLAY_CONTROLLER)
	PVR_DRM_MAKENAME(DISPLAY_CONTROLLER, _Cleanup)(dev);
#endif

	PVRCore_Cleanup();

#if defined(PDUMP)
	dbgdrv_cleanup();
#endif

	return 0;
}

DRI_DRM_STATIC int
PVRSRVDrmOpen(struct drm_device *dev, struct drm_file *file)
{
	while (!bInitComplete)
	{
		DEFINE_WAIT(sWait);

		prepare_to_wait(&sWaitForInit, &sWait, TASK_INTERRUPTIBLE);

		if (!bInitComplete)
		{
			PVR_TRACE(("%s: Waiting for module initialisation to complete", __FUNCTION__));

			schedule();
		}

		finish_wait(&sWaitForInit, &sWait);

		if (signal_pending(current))
		{
			return -ERESTARTSYS;
		}
	}

	if (bInitFailed)
	{
		PVR_DPF((PVR_DBG_ERROR, "%s: Module initialisation failed", __FUNCTION__));
		return -EINVAL;
	}

	return PVRSRVOpen(dev, file);
}

#if defined(SUPPORT_DRI_DRM_PLUGIN)
DRI_DRM_STATIC int
PVRSRVDrmRelease(struct drm_device *dev, struct drm_file *file)
#else
DRI_DRM_STATIC void
PVRSRVDrmPostClose(struct drm_device *dev, struct drm_file *file)
#endif
{
	PVRSRVRelease(file->driver_priv);

	file->driver_priv = NULL;

#if defined(SUPPORT_DRI_DRM_PLUGIN)
	return 0;
#endif
}

DRI_DRM_STATIC int
PVRDRMIsMaster(struct drm_device *dev, void *arg, struct drm_file *pFile)
{
	return 0;
}

#if defined(SUPPORT_DRI_DRM_EXT)
int
PVRDRM_Dummy_ioctl(struct drm_device *dev, void *arg, struct drm_file *pFile)
{
	return 0;
}
#endif

DRI_DRM_STATIC int
PVRDRMUnprivCmd(struct drm_device *dev, void *arg, struct drm_file *pFile)
{
	int ret = 0;

	LinuxLockMutexNested(&gPVRSRVLock, PVRSRV_LOCK_CLASS_BRIDGE);

	if (arg == NULL)
	{
		ret = -EFAULT;
	}
	else
	{
		IMG_UINT32 *pui32Args = (IMG_UINT32 *)arg;
		IMG_UINT32 ui32Cmd = pui32Args[0];
		IMG_UINT32 *pui32OutArg = (IMG_UINT32 *)arg;

		switch (ui32Cmd)
		{
			case PVR_DRM_UNPRIV_INIT_SUCCESFUL:
				*pui32OutArg = PVRSRVGetInitServerState(PVRSRV_INIT_SERVER_SUCCESSFUL) ? 1 : 0;
				break;

			default:
				ret = -EFAULT;
		}

	}

	LinuxUnLockMutex(&gPVRSRVLock);

	return ret;
}

#if defined(DISPLAY_CONTROLLER) && defined(PVR_DISPLAY_CONTROLLER_DRM_IOCTL)
static int
PVRDRM_Display_ioctl(struct drm_device *dev, void *arg, struct drm_file *pFile)
{
	int res;

	LinuxLockMutexNested(&gPVRSRVLock, PVRSRV_LOCK_CLASS_BRIDGE);

	res = PVR_DRM_MAKENAME(DISPLAY_CONTROLLER, _Ioctl)(dev, arg, pFile);

	LinuxUnLockMutex(&gPVRSRVLock);

	return res;
}
#endif

#if !defined(SUPPORT_DRI_DRM_EXT)

#if defined(DRM_IOCTL_DEF)
#define	PVR_DRM_IOCTL_DEF(ioctl, _func, _flags) DRM_IOCTL_DEF(DRM_##ioctl, _func, _flags)
#else
#define	PVR_DRM_IOCTL_DEF(ioctl, _func, _flags) DRM_IOCTL_DEF_DRV(ioctl, _func, _flags)
#endif

struct drm_ioctl_desc sPVRDrmIoctls[] = {
	PVR_DRM_IOCTL_DEF(PVR_SRVKM, PVRSRV_BridgeDispatchKM, DRM_UNLOCKED),
	PVR_DRM_IOCTL_DEF(PVR_IS_MASTER, PVRDRMIsMaster, DRM_MASTER | DRM_UNLOCKED),
	PVR_DRM_IOCTL_DEF(PVR_UNPRIV, PVRDRMUnprivCmd, DRM_UNLOCKED),
#if defined(PDUMP)
	PVR_DRM_IOCTL_DEF(PVR_DBGDRV, dbgdrv_ioctl, DRM_UNLOCKED),
#endif
#if defined(DISPLAY_CONTROLLER) && defined(PVR_DISPLAY_CONTROLLER_DRM_IOCTL)
	PVR_DRM_IOCTL_DEF(PVR_DISP, PVRDRM_Display_ioctl, DRM_MASTER | DRM_UNLOCKED)
#endif
};

#if !defined(SUPPORT_DRI_DRM_PLUGIN)
static int pvr_max_ioctl = DRM_ARRAY_SIZE(sPVRDrmIoctls);
#endif

#if !defined(SUPPORT_DRI_DRM_EXT) && !defined(SUPPORT_DRI_DRM_PLUGIN)
static int PVRSRVDrmProbe(struct platform_device *pDevice);
static int PVRSRVDrmRemove(struct platform_device *pDevice);
#endif	/* !defined(SUPPORT_DRI_DRM_EXT) */

#if defined(SUPPORT_DRI_DRM_PLUGIN)

static PVRSRV_DRM_PLUGIN sPVRDrmPlugin =
{
	.name = PVR_DRM_NAME,

	.open = PVRSRVDrmOpen,
	.load = PVRSRVDrmLoad,
	.unload = PVRSRVDrmUnload,

	.release = PVRSRVDrmRelease,

	.mmap = PVRMMap,

	.ioctls = sPVRDrmIoctls,
	.num_ioctls = DRM_ARRAY_SIZE(sPVRDrmIoctls),
	.ioctl_start = 0
};

#else	/* defined(SUPPORT_DRI_DRM_PLUGIN) */

static const struct file_operations sPVRFileOps = 
{
	.owner = THIS_MODULE,
	.open = drm_open,
	.release = drm_release,
	.unlocked_ioctl = drm_ioctl,
	.mmap = PVRMMap,
	.poll = drm_poll,
	.fasync = drm_fasync,
};

#if defined(CONFIG_OF)
static const struct of_device_id pvr_drm_of_match[] = {
	{ .compatible = PVR_DRM_NAME },
	{},
};
MODULE_DEVICE_TABLE(of, pvr_drm_of_match);
#endif

static struct drm_driver sPVRDrmDriver = 
{
	.driver_features = 0,
	.dev_priv_size = 0,
	.load = PVRSRVDrmLoad,
	.unload = PVRSRVDrmUnload,
	.open = PVRSRVDrmOpen,
	.postclose = PVRSRVDrmPostClose,
#if !defined(SUPPORT_DRM_MODESET)
	.suspend = PVRSRVDriverSuspend,
	.resume = PVRSRVDriverResume,
#endif
	.ioctls = sPVRDrmIoctls,
	.fops = &sPVRFileOps,
	.name = PVR_DRM_NAME,
	.desc = PVR_DRM_DESC,
	.date = PVR_DRM_DATE,
	.major = PVRVERSION_MAJ,
	.minor = PVRVERSION_MIN,
	.patchlevel = PVRVERSION_BUILD,
};

static struct platform_driver sPVRPlatDriver =
{
	.id_table = asPlatIdList,
	.driver =
	{
		.name = PVR_DRM_NAME,
	},
	.probe = PVRSRVDrmProbe,
	.remove = PVRSRVDrmRemove,
	.suspend = PVRSRVDriverSuspend,
	.resume = PVRSRVDriverResume,
	.shutdown = PVRSRVDriverShutdown,
};

#endif	/* defined(SUPPORT_DRI_DRM_PLUGIN) */

#if !defined(SUPPORT_DRI_DRM_EXT) && !defined(SUPPORT_DRI_DRM_PLUGIN)
static int
PVRSRVDrmProbe(struct platform_device *pDevice)
{
	PVR_TRACE(("PVRSRVDrmProbe"));
	pr_info("%s\n", __func__);

	gpsPVRLDMDev = pDevice;

	return drm_platform_init(&sPVRDrmDriver, gpsPVRLDMDev);
}

static int
PVRSRVDrmRemove(struct platform_device *pDevice)
{
	PVR_TRACE(("PVRSRVDrmRemove"));

	drm_platform_exit(&sPVRDrmDriver, gpsPVRLDMDev);
	return 0;
}
#endif

static int __init PVRSRVDrmInit(void)
{
	int iRes;

	pr_info("%s\n", __func__);

#if !defined(SUPPORT_DRI_DRM_PLUGIN)
	sPVRDrmDriver.num_ioctls = pvr_max_ioctl;
#endif

#if defined(SUPPORT_DRM_MODESET)
	sPVRDrmDriver.driver_features |= DRIVER_MODESET;
#endif

	/* Must come before attempting to print anything via Services */
	PVRDPFInit();

	iRes = platform_driver_register(&sPVRPlatDriver);
	return iRes;
}
	
static void __exit PVRSRVDrmExit(void)
{
	platform_driver_unregister(&sPVRPlatDriver);
}

/*
 * These macro calls define the initialisation and removal functions of the
 * driver.  Although they are prefixed `module_', they apply when compiling
 * statically as well; in both cases they define the function the kernel will
 * run to start/stop the driver.
*/
module_init(PVRSRVDrmInit);
module_exit(PVRSRVDrmExit);
#endif	/* !defined(SUPPORT_DRI_DRM_EXT) */

#endif	/* defined(SUPPORT_DRI_DRM) */
