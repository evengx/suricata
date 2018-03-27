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

#ifdef OS_WIN32

#include <inttypes.h>

// clang-format off
#include <winsock2.h>
#include <windows.h>
#include <ws2def.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
// clang-format on

#include "util-debug.h"
#include "util-error.h"

#include "win32-iphlp.h"
#include "win32-misc.h"

/**
 * \brief: get the adapter address list, which includes IP status/details
 */
static DWORD _GetAdaptersAddresses(IP_ADAPTER_ADDRESSES **pif_info_list)
{
    DWORD err = NO_ERROR;
    IP_ADAPTER_ADDRESSES *if_info_list;

    ULONG size = 0;
    err = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, NULL, &size);
    if (err != ERROR_BUFFER_OVERFLOW) {
        return err;
    }
    if_info_list = malloc((size_t)size);
    if (if_info_list == NULL) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    err = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, if_info_list, &size);
    if (err != NO_ERROR) {
        free(if_info_list);
        return err;
    }

    *pif_info_list = if_info_list;
    return NO_ERROR;
}

/**
 * \brief: get the maximum transmissible unit for the specified pcap device name
 */
int GetIfaceMTUWin32(const char *pcap_dev)
{

    int mtu = 0;

    DWORD err = NO_ERROR;
    IP_ADAPTER_ADDRESSES *if_info_list = NULL;

    /* adapter query functions require an index, not a name */
    ULONG if_index = if_nametoindex(pcap_dev);

    /* now search for the right adapter in the list */
    IP_ADAPTER_ADDRESSES *if_info = NULL;
    for (if_info = if_info_list; if_info != NULL; if_info = if_info->Next) {
        if (if_info->IfIndex == if_index) {
            break;
        }
    }
    if (if_info == NULL) {
        goto fail;
    }

    mtu = if_info->Mtu;

    free(if_info_list);
    free(wchar_pcap_dev);

    SCLogInfo("Found an MTU of %d for '%s'", mtu, pcap_dev);
    return mtu;

fail:
    free(if_info_list);

    const char *errbuf = NULL;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                           FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL, err, 0, (LPTSTR)&errbuf, 0, NULL);

    SCLogWarning(
            SC_ERR_SYSCALL,
            "Failure when trying to get MTU via syscall for '%s': %s (%" PRId32
            ")",
            pcap_dev, errbuf, (uint32_t)err);

    return -1;
}

/**
 * \brief: get the maximum transmissible unit for all devices on the system
 */
int GetGlobalMTUWin32()
{
    uint32_t mtu = 0;

    DWORD err = NO_ERROR;
    IP_ADAPTER_ADDRESSES *if_info_list = NULL;

    /* get a list of all adapters' data */
    err = _GetAdaptersAddresses(&if_info_list);
    if (err != NO_ERROR) {
        goto fail;
    }

    /* now search for the right adapter in the list */
    IP_ADAPTER_ADDRESSES *if_info = NULL;
    for (if_info = if_info_list; if_info != NULL; if_info = if_info->Next) {
        /* -1 (uint) is an invalid value */
        if (if_info->Mtu != (uint32_t)-1) {
            continue;
        }

        /* we want to return the largest MTU value so we allocate enough */
        if (if_info->Mtu > mtu) {
            mtu = if_info->Mtu;
        }
    }

    free(if_info_list);

    SCLogInfo("Found a global MTU of %" PRIu32, mtu);
    return (int)mtu;

fail:
    free(if_info_list);

    const char *errbuf = NULL;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                           FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL, err, 0, (LPTSTR)&errbuf, 0, NULL);

    SCLogWarning(
            SC_ERR_SYSCALL,
            "Failure when trying to get global MTU via syscall: %s (%" PRId32
            ")",
            errbuf, (uint32_t)err);

    return -1;
}

#endif /* OS_WIN32 */