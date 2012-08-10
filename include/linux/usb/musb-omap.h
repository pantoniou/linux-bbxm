/*
 * Copyright (C) 2011-2012 by Texas Instruments
 *
 * The Inventra Controller Driver for Linux is free software; you
 * can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 */

#ifndef __MUSB_OMAP_H__
#define __MUSB_OMAP_H__

enum omap_musb_vbus_id_status {
	OMAP_MUSB_UNKNOWN = 0,
	OMAP_MUSB_ID_GROUND,
	OMAP_MUSB_ID_FLOAT,
	OMAP_MUSB_VBUS_VALID,
	OMAP_MUSB_VBUS_OFF,
};

#ifdef CONFIG_USB_MUSB_OMAP2PLUS_MBOX_HELPER
void omap_musb_mailbox(enum omap_musb_vbus_id_status status);
enum omap_musb_vbus_id_status omap_musb_mailbox_set_callback(
		void (*func)(enum omap_musb_vbus_id_status));
#else
static inline void
omap_musb_mailbox(enum omap_musb_vbus_id_status status)
{
	/* nothing */
}

static inline enum omap_musb_vbus_id_status
omap_musb_mailbox_set_callback(void (*func)(enum omap_musb_vbus_id_status))
{
	/* always return unknown */
	return OMAP_MUSB_UNKNOWN;
}
#endif

#endif	/* __MUSB_OMAP_H__ */
