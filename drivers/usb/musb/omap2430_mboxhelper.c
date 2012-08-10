/*
 * Copyright (C) 2012 Texas Instruments
 *
 * Helper file to make sure the musb mailbox helper callback
 * works with any combination of modules/built-in configuration.
 *
 * This file is part of the Inventra Controller Driver for Linux.
 *
 * The Inventra Controller Driver for Linux is free software; you
 * can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *
 * The Inventra Controller Driver for Linux is distributed in
 * the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
 * License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with The Inventra Controller Driver for Linux ; if not,
 * write to the Free Software Foundation, Inc., 59 Temple Place,
 * Suite 330, Boston, MA  02111-1307  USA
 *
 */
#include <linux/module.h>
#include <linux/usb/musb-omap.h>

static DEFINE_SPINLOCK(omap_musb_callback_lock);
static void (*omap_musb_callback)(enum omap_musb_vbus_id_status status) = NULL;
static enum omap_musb_vbus_id_status omap_musb_last_status = OMAP_MUSB_UNKNOWN;

void omap_musb_mailbox(enum omap_musb_vbus_id_status status)
{
	unsigned long flags;

	spin_lock_irqsave(&omap_musb_callback_lock, flags);
	if (omap_musb_callback != NULL)
		(*omap_musb_callback)(status);
	omap_musb_last_status = status;
	spin_unlock_irqrestore(&omap_musb_callback_lock, flags);

}
EXPORT_SYMBOL_GPL(omap_musb_mailbox);

/* returns last status */
enum omap_musb_vbus_id_status omap_musb_mailbox_set_callback(
		void (*func)(enum omap_musb_vbus_id_status))
{
	unsigned long flags;
	enum omap_musb_vbus_id_status status;

	spin_lock_irqsave(&omap_musb_callback_lock, flags);
	omap_musb_callback = func;
	status = omap_musb_last_status;
	spin_unlock_irqrestore(&omap_musb_callback_lock, flags);

	return status;
}
EXPORT_SYMBOL_GPL(omap_musb_mailbox_set_callback);
