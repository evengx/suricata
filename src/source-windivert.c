/* Copyright (C) 2007-2014 Open Information Security Foundation
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
 * WinDivert emulation of netfilter_queue functionality to hook into Suricata's IPS mode.
 * Supported solely on Windows.
 * 
 */

#include "suricata-common.h"
#include "suricata.h"

#include "util-debug.h"
#include "util-error.h"
#include "util-byte.h"
#include "util-privs.h"
#include "util-device.h"

#include "runmodes.h"

#include "source-windivert-prototypes.h"
#include "source-windivert.h"

#ifndef WINDIVERT
/* Gracefully handle the case where no WinDivert support is compiled in */

TmECode NoWinDivertSupportExit(ThreadVars *, const void *, void **);

void TmModuleReceiveWinDivertRegister(void)
{
    tmm_modules[TMM_RECEIVEWINDIVERT].name = "ReceiveWinDivert";
    tmm_modules[TMM_RECEIVEWINDIVERT].ThreadInit = NoWinDivertSupportExit;
    tmm_modules[TMM_RECEIVEWINDIVERT].Func = NULL;
    tmm_modules[TMM_RECEIVEWINDIVERT].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_RECEIVEWINDIVERT].ThreadDeinit = NULL;
    tmm_modules[TMM_RECEIVEWINDIVERT].RegisterTests = NULL;
    tmm_modules[TMM_RECEIVEWINDIVERT].cap_flags = SC_CAP_NET_ADMIN;
    tmm_modules[TMM_RECEIVEWINDIVERT].flags = TM_FLAG_RECEIVE_TM;
}

void TmModuleVerdictWinDivertRegister(void)
{
    tmm_modules[TMM_VERDICTWINDIVERT].name = "VerdictWinDivert";
    tmm_modules[TMM_VERDICTWINDIVERT].ThreadInit = NoWinDivertSupportExit;
    tmm_modules[TMM_VERDICTWINDIVERT].Func = NULL;
    tmm_modules[TMM_VERDICTWINDIVERT].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_VERDICTWINDIVERT].ThreadDeinit = NULL;
    tmm_modules[TMM_VERDICTWINDIVERT].RegisterTests = NULL;
    tmm_modules[TMM_VERDICTWINDIVERT].cap_flags = SC_CAP_NET_ADMIN;
}

void TmModuleDecodeWinDivertRegister(void)
{
    tmm_modules[TMM_DECODEWINDIVERT].name = "DecodeWinDivert";
    tmm_modules[TMM_DECODEWINDIVERT].ThreadInit = NoWinDivertSupportExit;
    tmm_modules[TMM_DECODEWINDIVERT].Func = NULL;
    tmm_modules[TMM_DECODEWINDIVERT].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODEWINDIVERT].ThreadDeinit = NULL;
    tmm_modules[TMM_DECODEWINDIVERT].RegisterTests = NULL;
    tmm_modules[TMM_DECODEWINDIVERT].cap_flags = 0;
    tmm_modules[TMM_DECODEWINDIVERT].flags = TM_FLAG_DECODE_TM;
}

TmEcode NoWinDivertSupportExit(ThreadVars *tv, const void *initdata, void **data)
{
    SCLogError(
        SC_ERR_WINDIVERT_NOSUPPORT,
        "Error creating thread %s: you do not have support for WinDivert enabled; please recompile "
        "with --enable-windivert",
        tv->name);
        exit(EXIT_FAILURE);
}
#else
#endif /* WINDIVERT */