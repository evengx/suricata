/* Copyright (C) 2018 Open Information Security Foundation
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
 * \file
 *
 * \author Jacob Masen-Smith <jacob@evengx.com>
 * 
 * Isolation for iphlpapi.h functionality that defines values also defined in
 * Suricata headers, namely ICMP6_ error/status codes
 */

#ifndef __WIN32_IPHLP_H__
#define __WIN32_IPHLP_H__
#ifdef OS_WIN32

int GetIfaceMTUWin32(const char *pcap_dev);
int GetGlobalMTUWin32(void);

#endif /* OS_WIN32 */
#endif /* __WIN32_IPHLP_H__ */