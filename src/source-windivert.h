/* Copyright (C) 2007-2010 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 *
 * \file
 *
 * \author Jacob Masen-Smith <jacob@evengx.com>
 *
 */

#ifndef __SOURCE_WINDIVERT_H__
#define __SOURCE_WINDIVERT_H__

#ifdef WINDIVERT

#include "windivert.h"

/**
 * \brief WinDivertFilterConfig is the initial configuration of the filter.
 *
 * see https://reqrypt.org/windivert-doc.html#divert_open for more info
 */
typedef struct WinDivertFilterConfig_ {
    /* see https://reqrypt.org/windivert-doc.html#filter_language */
    const char *filter_string;
    WINDIVERT_LAYER layer;
    int16_t priority;
    uint64_t flags;
} WinDivertFilterConfig;

typedef struct WinDivertThreadVars_ WinDivertThreadVars;

typedef struct WinDivertPacketVars_ {
    WinDivertThreadVars *wd_tv;
    WINDIVERT_ADDRESS addr;
    bool verdicted;
} WinDivertPacketVars;

int WinDivertRegisterFilter(char *filter);
void *WinDivertGetThread(int thread);

#endif /* WINDIVERT */
#endif /* __SOURCE_WINDIVERT_H__ */