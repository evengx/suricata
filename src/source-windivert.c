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
 * WinDivert emulation of netfilter_queue functionality to hook into Suricata's
 * IPS mode. Supported solely on Windows.
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
    memset(&tmm_modules[TMM_RECEIVEWINDIVERT], 0, sizeof(TmModule));
    tmm_modules[TMM_RECEIVEWINDIVERT].name = "ReceiveWinDivert";
    tmm_modules[TMM_RECEIVEWINDIVERT].ThreadInit = NoWinDivertSupportExit;
    tmm_modules[TMM_RECEIVEWINDIVERT].flags = TM_FLAG_RECEIVE_TM;
}

void TmModuleVerdictWinDivertRegister(void)
{
    memset(&tmm_modules[TMM_VERDICTWINDIVERT], 0, sizeof(TmModule));
    tmm_modules[TMM_VERDICTWINDIVERT].name = "VerdictWinDivert";
    tmm_modules[TMM_VERDICTWINDIVERT].ThreadInit = NoWinDivertSupportExit;
}

void TmModuleDecodeWinDivertRegister(void)
{
    memset(&tmm_modules[TMM_DECODEWINDIVERT], 0, sizeof(TmModule));
    tmm_modules[TMM_DECODEWINDIVERT].name = "DecodeWinDivert";
    tmm_modules[TMM_DECODEWINDIVERT].ThreadInit = NoWinDivertSupportExit;
    tmm_modules[TMM_DECODEWINDIVERT].flags = TM_FLAG_DECODE_TM;
}

TmEcode NoWinDivertSupportExit(ThreadVars *tv, const void *initdata, void **data)
{
    SCLogError(
        SC_ERR_WINDIVERT_NOSUPPORT,
        "Error creating thread %s: you do not have support for WinDivert "
        "enabled; please recompile with --enable-windivert",
        tv->name);
        exit(EXIT_FAILURE);
}

#else /* implied we do have WinDivert support */

typedef struct WinDivertThreadVars_ {
    uint16_t filter_index;
} WinDivertThreadVars;

/* forward declarations of internal functions */
TmEcode ReceiveWinDivertLoop(ThreadVars *, void *, void *);
TmEcode ReceiveWinDivertThreadInit(ThreadVars *, const void *, void **);
TmECode ReceiveWinDivertThreadDeinit(ThreadVars *, void *);
void ReceiveWinDivertThreadExitStats(ThreadVars *, void *);

TmEcode VerdictWinDivert(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode VerdictWinDivertThreadInit(ThreadVars *, const void *, void **);
TmEcode VerdictWinDivertThreadDeinit(ThreadVars *, void *);

TmEcode DecodeWinDivert(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode DecodeWinDivertThreadInit(ThreadVars *, const void *, void **);
TmEcode DecodeWinDivertThreadDeinit(ThreadVars *, void *);

static bool WinDivertRecvPkt(WinDivertThreadVars *, WinDivertFilterVars *);

void TmModuleReceiveWinDivertRegister(void)
{
    TmModule *tm_ptr = &tmm_modules[TMM_RECEIVEWINDIVERT];
    memset(tm_ptr, 0, sizeof(TmModule));
    
    tm_ptr->name = "ReceiveWinDivert";
    tm_ptr->ThreadInit = ReceiveWinDivertThreadInit;
    tm_ptr->PktAcqLoop = ReceiveWinDivertLoop;
    tm_ptr->ThreadExitPrintStats = ReceiveWinDivertThreadExitStats;
    tm_ptr->ThreadDeinit = ReceiveWinDivertThreadDeinit;
    tm_ptr->flags = TM_FLAG_RECEIVE_TM;
}

void TmModuleVerdictWinDivertRegister(void)
{
    TmModule *tm_ptr = &tmm_modules[TMM_VERDICTWINDIVERT];
    memset(tm_ptr, 0, sizeof(TmModule));
    
    tm_ptr->name = "VerdictWinDivert";
    tm_ptr->ThreadInit = VerdictWinDivertThreadInit;
    tm_ptr->Func = VerdictWinDivert;
    tm_ptr->ThreadDeinit = VerdictWinDivertThreadDeinit;
}

void TmModuleDecodeWinDivertRegister(void)
{
    TmModule *tm_ptr = &tmm_modules[TMM_DECODEWINDIVERT];
    memset(tm_ptr, 0, sizeof(TmModule));
    
    tm_ptr->name = "DecodeWinDivert";
    tm_ptr->ThreadInit = DecodeWinDivertThreadInit;
    tm_ptr->Func = DecodeWinDivert;
    tm_ptr->ThreadDeinit = DecodeWinDivertThreadDeinit;
    tm_ptr->flags = TM_FLAG_DECODE_TM;
}

/**
 * \brief Main WinDivert packet receive pump
 */
TmEcode ReceiveWinDivertLoop(ThreadVars *tv, void *context, void *slot)
{
    SCEnter();

    WinDivertThreadVars *wd_tv = (WinDivertThreadVars *)context;
    WinDivertFilterVars *wd_fv = (WinDivertQueueVars *)WinDivertGetFilter(wd_tv->filter_index);

    while(true) {
        if (suricata_ctl_flags & SURICATA_STOP) {
            SCReturnInt(TM_ECODE_OK);
        }

        if (unlikely(!WinDivertRecvPkt(wd_tv, wd_fv))) {
            SCReturnInt(TM_ECODE_FAILED);
        }

        StatsSyncCountersIfSignalled(tv);
    }

    SCReturnInt(TM_ECODE_OK);
}

TmEcode ReceiveWinDivertThreadInit(ThreadVars *tv, const void *context, void **)
{
    WinDivertThreadVars *wd_thread_vars = (WinDivertThreadVars *)context;
    WinDivertFilterVars *wd_filter_vars = WinDivertGetFilter()
}

TmECode ReceiveWinDivertThreadDeinit(ThreadVars *, void *);
void ReceiveWinDivertThreadExitStats(ThreadVars *, void *);

TmEcode VerdictWinDivert(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode VerdictWinDivertThreadInit(ThreadVars *, const void *, void **);
TmEcode VerdictWinDivertThreadDeinit(ThreadVars *, void *);

TmEcode DecodeWinDivert(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode DecodeWinDivertThreadInit(ThreadVars *, const void *, void **);
TmEcode DecodeWinDivertThreadDeinit(ThreadVars *, void *);

static TmEcode WinDivertRecvPkt(WinDivertThreadVars *wd_tv, WinDivertFilterVars *wd_fv)
{
    SCEnter();

    /* make sure we have at least one packet in the packet pool, to prevent us
     * from alloc'ing packets at line rate
     */
    PacketPoolWait();

    /* obtain a packet buffer */
    Packet *p = PacketGetFromQueueOrAlloc();
    if (unlikely(p == NULL)) {
        SCLogDebug("PacketGetFromQueueOrAlloc() - failed to obtain Packet buffer");
        SCReturnInt(TM_ECODE_FAILED);
    }
    PKT_SET_SRC(p, PKT_SRC_WIRE);

    /* WinDivert needs to be fed a buffer, so we must make one available. It is
     * highly likely we'll encounter segmentation offload so we'll just give our
     * pool packets external buffers.
     */ 
    PacketCallocExtPkt(p, MAX_PAYLOAD_SIZE);

    bool success = WinDivertRecv(
        wd_fv->filter_handle,
        p->ext_pkt,
        MAX_PAYLOAD_SIZE,
        p->windivert_v.addr,
        p->pkt_len);
    if (!success) {
        SCReturnInt(TM_ECODE_FAILED);
    }

    p->windivert_v.filter_handle = wd_fv->filter_handle;

    /* Do the packet processing by calling TmThreadsSlotProcessPkt, this will,
     * depending on the running mode, pass the packet to the treatment functions
     * or push it to a packet pool. So processing time can vary.
     */
    if (TmThreadsSlotProcessPkt(wd_tv->tv, /* \todo what var? */, p) != TM_ECODE_OK) {
        TmqhOutputPacketpool(ptv->tv, p);
        SCReturnInt(TM_ECODE_FAILED);
    }

    SCReturnInt(TM_ECODE_OK);
}

#endif /* WINDIVERT */