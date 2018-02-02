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

typedef void *WinDivertHandle;

typedef struct WinDivertFilterVars_ {
    WinDivertHandle filter_handle;

    /* counters */
    uint32_t pkts;
    uint64_t bytes;
    uint32_t errs;
    uint32_t accepted;
    uint32_t dropped;
    uint32_t replaced;
    
} WinDivertFilterVars;

typedef struct WinDivertPacketVars_ {
    WinDivertHandle filter_handle;
} WinDivertPacketVars;

int WinDivertRegisterFilter(char *filter);
void *WinDivertGetFilter(int number);
void *WinDivertGetThread(int number);

#endif /* WINDIVERT */
#endif /* __SOURCE_WINDIVERT_H__ */