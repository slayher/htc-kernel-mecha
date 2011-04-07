/* arch/arm/mach-msm/panel_id.h
 * Copyright (C) 2010 HTC Corporation.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */


#ifndef __PANEL_ID_H
#define __PANEL_ID_H

extern int panel_type;

/* BIT0 - BIT15 : panel id */
/* BIT16 - BIT18 : backlight interface */
/* BIT19- BIT21 : display interface */
/* BIT22- BIT24 : color depth */
/* BIT25- BIT27 : lcm revision */
/* BIT28- BIT31 : reserved */

#define BL_SHIFT        16
#define BL_MASK         (0x7 << BL_SHIFT)

#define BL_SPI          (0 << BL_SHIFT)
#define BL_MDDI         (1 << BL_SHIFT)
#define BL_I2C          (2 << BL_SHIFT)
#define BL_UP           (3 << BL_SHIFT)

#define IF_SHIFT        19
#define IF_MASK         (0x7 << IF_SHIFT)

#define IF_LCDC         (0 << IF_SHIFT)
#define IF_MDDI         (1 << IF_SHIFT)
#define IF_MIPI         (2 << IF_SHIFT)

#define DEPTH_SHIFT     22
#define DEPTH_MASK      (0x7 << DEPTH_SHIFT)

#define DEPTH_RGB565    (0 << DEPTH_SHIFT)
#define DEPTH_RGB666    (1 << DEPTH_SHIFT)
#define DEPTH_RGB888    (2 << DEPTH_SHIFT)


#define REV_SHIFT       25
#define REV_MASK        (0x7 << REV_SHIFT)

#define REV_0           (0 << REV_SHIFT)
#define REV_1           (1 << REV_SHIFT)
#define REV_2           (2 << REV_SHIFT)



#define PANEL_ID_START          0x0F

#define PANEL_ID_SAGA_SONY      (0x10 | BL_SPI | IF_LCDC | DEPTH_RGB666)

#define PANEL_ID_END            0xFFFF

#endif	//__PANEL_ID_H

