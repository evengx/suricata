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
}*

#else /* implied we do have WinDivert support */

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

static bool WinDivertRecvPkt(WinDivertThreadVars *);

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
    wd_tv->slot = ((TmSlot *)slot)->slot_next;

    while(true) {
        if (suricata_ctl_flags & SURICATA_STOP) {
            SCReturnInt(TM_ECODE_OK);
        }

        if (unlikely(WinDivertRecvPkt(wd_tv) != TM_ECODE_OK)) {
            SCReturnInt(TM_ECODE_FAILED);
        }

        StatsSyncCountersIfSignalled(tv); 
    }

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief Init function for ReceiveWinDivert
 * 
 * ReceiveWinDivertThreadInit sets up receiving packets via WinDivert.
 * 
 * \param tv pointer to generic thread vars
 * \param initdata pointer to the interface passed from the user
 * \param context out-pointer to the WinDivert-specific thread vars
 */
TmEcode ReceiveWinDivertThreadInit(ThreadVars *tv, const void *initdata, void **context)
{
    SCEnter();
    
    WinDivertFilterConfig *wd_filter_cfg = (WinDivertFilterConfig *)initdata;

    if (wd_filter_cfg == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "initdata == NULL");
        SCReturnInt(TM_ECODE_FAILED);
    }

    WinDivertThreadVars *wd_thread_vars = SCMalloc(sizeof(WinDivertThreadVars));
    if (unlikely(wd_thread_vars == NULL)) {
        SCReturnInt(TM_ECODE_FAILED);
    }
    memset(wd_thread_vars, 0, sizeof(WinDivertThreadVars));
    *context = wd_thread_vars;

    wd_thread_vars->filter_handle = WinDivertOpen(
        wd_filter_cfg->filter_string,
        wd_filter_cfg->layer,
        wd_filter_cfg->priority,
        wd_filter_cfg->flags);

    if (wd_thread_vars->filter_handle == INVALID_HANDLE_VALUE) {
        SCLogError(GetLastError(), "WinDivertOpen failed")
        SCReturnInt(TM_ECODE_FAILED);
    }

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief Deinit function releases resources at exit.
 * 
 * \param tv pointer to generic thread vars
 * \param context pointer to WinDivert-specific thread vars 
 */
TmECode ReceiveWinDivertThreadDeinit(ThreadVars *tv, void *context)
{
    WinDivertThreadVars *wd_tv = (WinDivertThreadVars *)context;

    if (!WinDivertClose(wd_tv->filter_handle)) {
        SCLogError(GetLastError(), "WinDivertClose failed");
        SCReturnInt(TM_ECODE_FAILED);
    }
    
    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief ExitStats prints stats to stdout at exit
 * 
 * \param tv pointer to generic thread vars
 * \param context pointer to WinDivert-specific thread vars 
 */
void ReceiveWinDivertThreadExitStats(ThreadVars *tv, void *context)
{
    WinDivertThreadVars *wd_tv = (WinDivertThreadVars *)context;

    SCLogInfo(
        "(%s) Packets %" PRIu32 ", Bytes %" PRIu64 ", Errors %" PRIu32 "",
        tv->name,
        wd_tv->pkts,
        wd_tv->bytes,
        wd_tv->errs);
    SCLogInfo(
        "(%s) Verdict: Accepted %" PRIu32 ", Dropped %" PRIu32 ", Replaced %" PRIu32 "",
        tv->name,
        wd_tv->stats.counter_ips_accepted,
        wd_tv->stats.counter_ips_dropped,
        wd_tv->stats.counter_ips_replaced);
}

/**
 * \brief WinDivert verdict module packet entry function
 */
TmEcode VerdictWinDivert(ThreadVars *tv, Packet *p, void *context, PacketQueue *pq, PacketQueue *postpq)
{
    WinDivertThreadVars *wd_tv = (WinDivertThreadVars *)context;

    
}

TmEcode VerdictWinDivertThreadInit(ThreadVars *, const void *, void **);
TmEcode VerdictWinDivertThreadDeinit(ThreadVars *, void *);

TmEcode DecodeWinDivert(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode DecodeWinDivertThreadInit(ThreadVars *, const void *, void **);
TmEcode DecodeWinDivertThreadDeinit(ThreadVars *, void *);

static TmEcode WinDivertRecvPkt(WinDivertThreadVars *wd_tv)
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
        wd_tv->filter_handle,
        p->ext_pkt,
        MAX_PAYLOAD_SIZE,
        p->windivert_v.addr,
        p->pkt_len);
    if (!success) {
        SCLogError(GetLastError(), "WinDivertRecv failed")
        SCReturnInt(TM_ECODE_FAILED);
    }

    p->windivert_v.filter_handle = wd_tv->filter_handle;

    /* Do the packet processing by calling TmThreadsSlotProcessPkt, this will,
     * depending on the running mode, pass the packet to the treatment functions
     * or push it to a packet pool. So processing time can vary.
     */
    if (TmThreadsSlotProcessPkt(wd_tv->tv, wd_tv->slot, p) != TM_ECODE_OK) {
        TmqhOutputPacketpool(wd_tv->tv, p);
        SCReturnInt(TM_ECODE_FAILED);
    }

    SCReturnInt(TM_ECODE_OK);
}

#endif /* WINDIVERT */