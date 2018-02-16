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
#include "tm-threads.h"

#include "util-byte.h"
#include "util-debug.h"
#include "util-device.h"
#include "util-error.h"
#include "util-privs.h"

#include "runmodes.h"

#include "source-windivert-prototypes.h"
#include "source-windivert.h"

#ifndef WINDIVERT
/* Gracefully handle the case where no WinDivert support is compiled in */

TmEcode NoWinDivertSupportExit(ThreadVars *, const void *, void **);

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

TmEcode NoWinDivertSupportExit(ThreadVars *tv, const void *initdata,
                               void **data)
{
    SCLogError(
            SC_ERR_WINDIVERT_NOSUPPORT,
            "Error creating thread %s: you do not have support for WinDivert "
            "enabled; please recompile with --enable-windivert",
            tv->name);
    exit(EXIT_FAILURE);
}

#else /* implied we do have WinDivert support */

typedef void *WinDivertHandle;

typedef struct WinDivertThreadVars_ {
    WinDivertHandle filter_handle;
    /* only needed for setup/teardown; Recv/Send are internally synchronized */
    SCMutex filter_handle_mutex;

    TmSlot *slot;

    /* counters */
    uint32_t pkts;
    uint64_t bytes;
    uint32_t errs;
    SCRWLock counters_mutex;

    CaptureStats stats;
} WinDivertThreadVars;

static WinDivertThreadVars *g_wd_tv;

void *WinDivertGetThread(int thread)
{
    return g_wd_tv;
}

/* forward declarations of internal functions */
/* Receive functions */
TmEcode ReceiveWinDivertLoop(ThreadVars *, void *, void *);
TmEcode ReceiveWinDivertThreadInit(ThreadVars *, const void *, void **);
TmEcode ReceiveWinDivertThreadDeinit(ThreadVars *, void *);
void ReceiveWinDivertThreadExitStats(ThreadVars *, void *);

/* Verdict functions */
TmEcode VerdictWinDivert(ThreadVars *, Packet *, void *, PacketQueue *,
                         PacketQueue *);
TmEcode VerdictWinDivertThreadInit(ThreadVars *, const void *, void **);
TmEcode VerdictWinDivertThreadDeinit(ThreadVars *, void *);

/* Decode functions */
TmEcode DecodeWinDivert(ThreadVars *, Packet *, void *, PacketQueue *,
                        PacketQueue *);
TmEcode DecodeWinDivertThreadInit(ThreadVars *, const void *, void **);
TmEcode DecodeWinDivertThreadDeinit(ThreadVars *, void *);

/* internal helper functions */
static TmEcode WinDivertRecvHelper(ThreadVars *tv, WinDivertThreadVars *);
static TmEcode WinDivertVerdictHelper(Packet *);
static TmEcode WinDivertCloseHelper(WinDivertThreadVars *);

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

    while (true) {
        if (suricata_ctl_flags & SURICATA_STOP) {
            SCReturnInt(TM_ECODE_OK);
        }

        if (unlikely(WinDivertRecvHelper(tv, wd_tv) != TM_ECODE_OK)) {
            SCReturnInt(TM_ECODE_FAILED);
        }

        StatsSyncCountersIfSignalled(tv);
    }

    SCReturnInt(TM_ECODE_OK);
}

static TmEcode WinDivertRecvHelper(ThreadVars *tv, WinDivertThreadVars *wd_tv)
{
    SCEnter();

    /* make sure we have at least one packet in the packet pool, to prevent us
     * from alloc'ing packets at line rate
     */
    PacketPoolWait();

    /* obtain a packet buffer */
    Packet *p = PacketGetFromQueueOrAlloc();
    if (unlikely(p == NULL)) {
        SCLogDebug(
                "PacketGetFromQueueOrAlloc() - failed to obtain Packet buffer");
        SCReturnInt(TM_ECODE_FAILED);
    }
    PKT_SET_SRC(p, PKT_SRC_WIRE);

    /* WinDivert needs to be fed a buffer, so we must make one available. It is
     * highly likely we'll encounter segmentation offload so we'll just give our
     * pool packets external buffers.
     */
    PacketCallocExtPkt(p, MAX_PAYLOAD_SIZE);

    bool success =
            WinDivertRecv(wd_tv->filter_handle, p->ext_pkt, MAX_PAYLOAD_SIZE,
                          &p->windivert_v.addr, &GET_PKT_LEN(p));
    if (!success) {
        SCLogError(GetLastError(), "WinDivertRecv failed");
        SCReturnInt(TM_ECODE_FAILED);
    }

    p->windivert_v.wd_tv = wd_tv;

    SCRWLockWRLock(wd_tv->counters_mutex);
    wd_tv->pkts++;
    wd_tv->bytes += GET_PKT_LEN(p);
    SCRWLockUnlock(wd_tv->counters_mutex);

    /* Do the packet processing by calling TmThreadsSlotProcessPkt, this will,
     * depending on the running mode, pass the packet to the treatment functions
     * or push it to a packet pool. So processing time can vary.
     */
    if (TmThreadsSlotProcessPkt(tv, wd_tv->slot, p) != TM_ECODE_OK) {
        TmqhOutputPacketpool(tv, p);
        SCReturnInt(TM_ECODE_FAILED);
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
TmEcode ReceiveWinDivertThreadInit(ThreadVars *tv, const void *initdata,
                                   void **context)
{
    SCEnter();

    WinDivertFilterConfig *wd_filter_cfg = (WinDivertFilterConfig *)initdata;

    if (wd_filter_cfg == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "initdata == NULL");
        SCReturnInt(TM_ECODE_FAILED);
    }

    WinDivertThreadVars *wd_tv = SCMalloc(sizeof(WinDivertThreadVars));
    if (unlikely(wd_tv == NULL)) {
        SCReturnInt(TM_ECODE_FAILED);
    }

    memset(wd_tv, 0, sizeof(WinDivertThreadVars));
    *context = wd_tv;

    SCMutexInit(wd_tv->filter_handle_mutex, NULL);
    SCRWLockInit(wd_tv->counters_mutex, NULL);

    wd_tv->filter_handle =
            WinDivertOpen(wd_filter_cfg->filter_string, wd_filter_cfg->layer,
                          wd_filter_cfg->priority, wd_filter_cfg->flags);

    if (wd_tv->filter_handle == INVALID_HANDLE_VALUE) {
        SCLogError(GetLastError(), "WinDivertOpen failed");
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
TmEcode ReceiveWinDivertThreadDeinit(ThreadVars *tv, void *context)
{
    SCEnter();

    WinDivertThreadVars *wd_tv = (WinDivertThreadVars *)context;

    SCReturnInt(WinDivertCloseHelper(wd_tv));
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

    SCRWLockRDLock(wd_tv->counters_mutex);

    SCLogInfo("(%s) Packets %" PRIu32 ", Bytes %" PRIu64 ", Errors %" PRIu32 "",
              tv->name, wd_tv->pkts, wd_tv->bytes, wd_tv->errs);
    SCLogInfo("(%s) Verdict: Accepted %" PRIu32 ", Dropped %" PRIu32
              ", Replaced %" PRIu32 "",
              tv->name, wd_tv->stats.counter_ips_accepted,
              wd_tv->stats.counter_ips_blocked,
              wd_tv->stats.counter_ips_replaced);

    SCRWLockUnlock(wd_tv->counters_mutex);
}

/**
 * \brief WinDivert verdict module packet entry function
 */
TmEcode VerdictWinDivert(ThreadVars *tv, Packet *p, void *context,
                         PacketQueue *pq, PacketQueue *postpq)
{
    SCEnter();

    TmEcode ret = TM_ECODE_OK;

    /* \todo do we need to specifically handle tunnel packets like NFQ? */
    ret = WinDivertVerdictHelper(p);
    if (ret != TM_ECODE_OK) {
        SCReturnInt(ret);
    }

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief internal helper function to do the bulk of verdict work
 */
static TmEcode WinDivertVerdictHelper(Packet *p)
{
    WinDivertThreadVars *wd_tv = p->windivert_v.wd_tv;

    p->windivert_v.verdicted = true;

    /* can't verdict a "fake" packet */
    if (PKT_IS_PSEUDOPKT(p)) {
        SCReturnInt(TM_ECODE_OK);
    }

    /* the handle has been closed and we can no longer use it */
    if (wd_tv->filter_handle == INVALID_HANDLE_VALUE) {
        SCReturnInt(TM_ECODE_OK);
    }

    /* DROP simply means we do nothing; the WinDivert driver does the rest. */
    if (PACKET_TEST_ACTION(p, ACTION_DROP)) {
        SCReturnInt(TM_ECODE_OK);
    }

    bool success = WinDivertSend(wd_tv->filter_handle, GET_PKT_DATA(p),
                                 GET_PKT_LEN(p), &p->windivert_v.addr, NULL);

    if (unlikely(!success)) {
        SCReturnInt(TM_ECODE_FAILED);
    }

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief init the verdict thread, which is piggybacked off the receive thread
 */
TmEcode VerdictWinDivertThreadInit(ThreadVars *tv, const void *initdata,
                                   void **context)
{
    SCEnter();

    WinDivertThreadVars *wd_tv = (WinDivertThreadVars *)initdata;

    CaptureStatsSetup(tv, &wd_tv->stats);

    *context = wd_tv;

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief deinit the verdict thread and shut down the WinDivert driver if it's
 * still up.
 */
TmEcode VerdictWinDivertThreadDeinit(ThreadVars *tv, void *context)
{
    SCEnter();

    WinDivertThreadVars *wd_tv = (WinDivertThreadVars *)context;

    SCReturnInt(WinDivertCloseHelper(wd_tv));
}

/**
 * \brief decode a raw packet submitted to suricata from the WinDivert driver
 *
 * All WinDivert packets are IPv4/v6, but do not include the network layer to
 * differentiate the two, so instead we must check the version and go from
 * there.
 */
TmEcode DecodeWinDivert(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq,
                        PacketQueue *postpq)
{
    SCEnter();

    IPV4Hdr *ip4h = (IPV4Hdr *)GET_PKT_DATA(p);
    IPV6Hdr *ip6h = (IPV6Hdr *)GET_PKT_DATA(p);
    DecodeThreadVars *d_tv = (DecodeThreadVars *)data;

    /* XXX HACK: flow timeout can call us for injected pseudo packets
     *           see bug: https://redmine.openinfosecfoundation.org/issues/1107
     */
    if (PKT_IS_PSEUDOPKT(p))
        SCReturnInt(TM_ECODE_OK);

    DecodeUpdatePacketCounters(tv, d_tv, p);

    if (IPV4_GET_RAW_VER(ip4h) == 4) {
        SCLogDebug("IPv4 packet");
        DecodeIPV4(tv, d_tv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);
    } else if (IPV6_GET_RAW_VER(ip6h) == 6) {
        SCLogDebug("IPv6 packet");
        DecodeIPV6(tv, d_tv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);
    } else {
        SCLogDebug("packet unsupported by WinDivert, first byte: %02x",
                   *GET_PKT_DATA(p));
    }

    PacketDecodeFinalize(tv, d_tv, p);

    SCReturnInt(TM_ECODE_OK);
}

TmEcode DecodeWinDivertThreadInit(ThreadVars *tv, const void *initdata,
                                  void **context)
{
    SCEnter();

    DecodeThreadVars *d_tv = DecodeThreadVarsAlloc(tv);
    if (d_tv == NULL) {
        SCReturnInt(TM_ECODE_FAILED);
    }

    DecodeRegisterPerfCounters(d_tv, tv);

    *context = d_tv;

    SCReturnInt(TM_ECODE_OK);
}

TmEcode DecodeWinDivertThreadDeinit(ThreadVars *tv, void *context)
{
    SCEnter();

    if (context != NULL) {
        DecodeThreadVarsFree(tv, context);
    }

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief helper function for use with ThreadDeinit functions
 */
static TmEcode WinDivertCloseHelper(WinDivertThreadVars *wd_tv)
{
    TmEcode ret = TM_ECODE_OK;

    SCMutexLock(wd_tv->filter_handle_mutex);

    /* check if there's nothing to close already */
    if (wd_tv == INVALID_HANDLE_VALUE || wd_tv == NULL) {
        goto unlock;
    }

    if (!WinDivertClose(wd_tv->filter_handle)) {
        SCLogError(GetLastError(), "WinDivertClose failed");
        ret = TM_ECODE_FAILED;
        goto unlock;
    }

unlock:
    SCMutexUnlock(wd_tv->filter_handle_mutex);
    SCReturnInt(ret);
}

#endif /* WINDIVERT */