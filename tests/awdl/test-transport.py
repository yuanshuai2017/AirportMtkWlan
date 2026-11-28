"""Compile the actual d16 transport and window helpers under sanitizers."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
body = r"""
#include <cassert>
#include <cstring>
#include <HAL/MtkAwdlData.hpp>
#include <HAL/MtkAwdlAnnouncement.hpp>
#include <HAL/MtkAwdlPeerIdentity.hpp>
#include <HAL/Awdl/AWDLPeerSchedule.hpp>

static void expectScheduledResume(const ItlAWDL::PeerSchedule &peer, uint64_t start,
                                  uint64_t resume, uint64_t earlyUS, uint64_t lateUS)
{
    ItlAWDL::PeerPauseState state = {};
    const uint64_t limit = peer.pauseLimitDataUS(start, earlyUS, lateUS);
    assert(limit > resume - start);
    assert(limit == resume - start + 4000);
    assert(peer.shouldPauseData(start, earlyUS, lateUS));
    assert(state.step(true, start, limit) == 1);
    for (uint64_t now = start + 1; now < resume; ++now) {
        const bool wantPause = peer.shouldPauseData(now, earlyUS, lateUS);
        assert(wantPause);
        assert(state.step(wantPause, now) == 0);
        assert(state.paused);
    }
    assert(!peer.shouldPauseData(resume, earlyUS, lateUS));
    assert(state.step(false, resume) == -1);
    assert(!state.paused && state.forcedResumes == 0);
}

static void testDataPause()
{
    using namespace ItlAWDL;
    constexpr uint64_t anchor = 100000, earlyUS = 15000, lateUS = 4000;
    PeerSyncInfo sync = {};
    sync.awPeriodTU = 16;
    sync.downCounterTU = 64;
    const uint8_t channels[kPeerSeqEntries] = {
        149, 149, 149, 149, 157, 157, 157, 157, 6, 149, 149, 149, 157, 157, 157, 157
    };
    memcpy(sync.channels, channels, sizeof(channels));
    PeerSchedule peer = {};
    assert(peer.pauseLimitDataUS(anchor, earlyUS, lateUS) == kPeerPauseMaxUS);
    peer.assumeZero = true;
    peer.note(sync, anchor, 157);

    const uint64_t away = anchor + 8 * peer.eawUS;
    const uint64_t resume = away + 4 * peer.eawUS + lateUS;
    assert(!peer.shouldPauseData(away - earlyUS - 1, earlyUS, lateUS));
    expectScheduledResume(peer, away - earlyUS, resume, earlyUS, lateUS);
    expectScheduledResume(peer, away + peer.eawUS + 17000, resume, earlyUS, lateUS);
    // An early margin longer than one entry can cross two present entries.
    const uint64_t multiEarlyUS = peer.eawUS + earlyUS;
    expectScheduledResume(peer, away - multiEarlyUS, resume, multiEarlyUS, lateUS);

    memset(sync.channels, 157, sizeof(sync.channels));
    peer.note(sync, anchor, 157);
    assert(peer.pauseLimitDataUS(anchor, earlyUS, lateUS) == kPeerPauseMaxUS);
    memset(sync.channels, 149, sizeof(sync.channels));
    peer.note(sync, anchor, 157);
    assert(peer.pauseLimitDataUS(anchor + kPeerScheduleStaleUS, earlyUS, lateUS) == kPeerPauseMaxUS);
    const uint64_t limit = peer.pauseLimitDataUS(anchor, earlyUS, lateUS);
    assert(limit == kPeerPauseCeilingUS);
    PeerPauseState state = {};
    assert(state.step(peer.shouldPauseData(anchor, earlyUS, lateUS), anchor, limit) == 1);
    const uint64_t deadline = anchor + limit;
    assert(state.step(peer.shouldPauseData(deadline - 1, earlyUS, lateUS), deadline - 1) == 0);
    assert(peer.shouldPauseData(deadline, earlyUS, lateUS));
    assert(state.step(true, deadline) == -1);
    assert(!state.paused && state.forcedResumes == 1);
    assert(peer.usUntilAway(deadline) == 0 && state.probeAfterTimeout(true, deadline));
    assert(!state.probeAfterTimeout(false, deadline));
    assert(!state.probeAfterTimeout(true, deadline + kPeerPauseHoldOffUS));
}

static const uint8_t quarterPresence[ItlAWDL::kPeerSeqEntries] = {
    149, 149, 149, 149, 149, 149, 157, 157, 6, 149, 149, 149, 149, 149, 157, 157
};

static void testSequenceTransition()
{
    using namespace ItlAWDL;
    using Update = PeerSchedule::Update;
    constexpr uint64_t anchor = 100000, earlyUS = 15000, lateUS = 4000;
    PeerSyncInfo sync = {};
    sync.awPeriodTU = 16;
    sync.downCounterTU = 64;
    const uint8_t halfPresence[kPeerSeqEntries] = {
        149, 149, 149, 149, 157, 157, 157, 157, 6, 149, 149, 149, 157, 157, 157, 157
    };
    memcpy(sync.channels, halfPresence, sizeof(halfPresence));
    PeerSchedule peer = {};
    peer.note(sync, anchor, 157);
    peer.calibrated = true;
    peer.offset = 8;
    PeerWindowEvidence evidence;
    for (unsigned i = 0; i < 8; ++i)
        evidence.add(true);

    PeerPauseState state = {};
    const uint64_t away = anchor + 8 * peer.eawUS;
    const uint64_t start = away - earlyUS;
    const uint64_t oldLimit = peer.pauseLimitDataUS(start, earlyUS, lateUS);
    assert(state.step(peer.shouldPauseData(start, earlyUS, lateUS), start, oldLimit) == 1);

    const uint64_t switched = away - 4096;
    sync.awCounter = 31;
    sync.downCounterTU = 4;
    memcpy(sync.channels, quarterPresence, sizeof(quarterPresence));
    assert(peer.note(sync, switched, 157) == Update::Sequence);
    assert(peer.phaseErrorUS == 0 && peer.anchorEndUS == away);
    assert(peer.known() && peer.entryOffset() == 8 && peer.decalibrations == 0);
    assert(peer.sequenceChanges == 1 && peer.presentEntries() == 4);
    assert(evidence.reanchor(peer.known()) && evidence.matches() == 8);
    state.refreshLimit(switched, peer.pauseLimitDataUS(switched, earlyUS, lateUS));

    const uint64_t resume = away + 6 * peer.eawUS + lateUS;
    assert(state.limitUS > oldLimit && start + state.limitUS == resume + 4000);
    for (uint64_t now = switched; now < resume; ++now) {
        assert(evidence.reliable() && peer.timingUsable(now, false));
        assert(state.step(peer.shouldPauseData(now, earlyUS, lateUS), now) == 0 && state.paused);
    }
    assert(state.step(peer.shouldPauseData(resume, earlyUS, lateUS), resume) == -1);
    assert(!state.paused && state.forcedResumes == 0);

    // A changed bitmap with discontinuous AW numbering is a phase jump.
    ++sync.channels[0];
    sync.awCounter += 4;
    assert(peer.note(sync, switched + 1024, 157) == Update::Phase);
    assert(peer.sequenceChanges == 2 && !peer.known() && peer.decalibrations == 1);
    assert(!evidence.reanchor(false) && !evidence.reliable());

    const uint64_t stale = peer.heardUS + kPeerScheduleStaleUS;
    for (unsigned i = 0; i < 8; ++i)
        evidence.add(true);
    assert(!peer.timingUsable(stale, false) && !peer.shouldPauseData(stale, earlyUS, lateUS));
    assert(peer.note(sync, stale, 157) == Update::Gap);
    assert(!evidence.reanchor(false) && evidence.samples == 0);

    // A refreshed limit must stay bounded by the original start time,
    // even if the peer never returns and each new prediction extends it.
    state = {};
    assert(state.step(true, stale) == 1);
    const uint64_t deadline = stale + kPeerPauseCeilingUS;
    state.refreshLimit(stale + 100000, kPeerPauseCeilingUS);
    state.refreshLimit(deadline - 1, kPeerPauseCeilingUS);
    assert(state.step(true, deadline - 1) == 0 && state.paused);
    assert(state.step(true, deadline) == -1);
    assert(!state.paused && state.forcedResumes == 1);
}

static void testEquivalentOffsets()
{
    using namespace ItlAWDL;
    constexpr uint64_t anchor = 100000, into = 4000;
    PeerSyncInfo sync = {};
    sync.awPeriodTU = 16;
    sync.downCounterTU = 64;
    memcpy(sync.channels, quarterPresence, sizeof(quarterPresence));
    PeerSchedule peer = {};
    peer.assumeZero = true;
    peer.note(sync, anchor, 157);
    // Contradictions in two entries refute assumed offset zero.
    for (unsigned i = 0; i < 100; ++i) {
        peer.notePeerEntry(0, into);
        peer.notePeerEntry(1, into);
    }
    assert(peer.refuted && !peer.known() && peer.refutations == 1);

    for (unsigned i = 0; i < kPeerCalibrateFrames; ++i)
        peer.notePeerEntry(6, into);
    // One observed entry still leaves distinct presence bitmaps tied.
    assert(peer.refuted && !peer.known());
    for (unsigned i = 0; i < 8; ++i) {
        peer.notePeerEntry(7, into);
        peer.notePeerEntry(14, into);
        peer.notePeerEntry(15, into);
    }
    assert(peer.calibrated && !peer.refuted && peer.entryOffset() == 0);
    assert(peer.calibrations == 1);
}

static void testIdleSequence()
{
    using namespace ItlAWDL;
    constexpr uint64_t anchor = 100000, earlyUS = 15000, lateUS = 4000;
    PeerSyncInfo sync = {};
    sync.awPeriodTU = 16;
    sync.downCounterTU = 64;
    const uint8_t channels[kPeerSeqEntries] = {
        157, 0, 149, 0, 0, 0, 0, 0, 6, 0, 149, 0, 0, 0, 0, 0
    };
    memcpy(sync.channels, channels, sizeof(channels));
    PeerSchedule peer = {};
    peer.assumeZero = true;
    peer.note(sync, anchor, 157);
    assert(peer.presentEntries() == 1);  // Zero is still not proof of presence.
    for (unsigned slot = 0; slot < kPeerSeqEntries; ++slot) {
        const uint64_t midSlot = anchor + slot * peer.eawUS + peer.eawUS / 2;
        const bool away = slot == 2 || slot == 8 || slot == 10;
        assert(peer.awayForData(slot) == away);
        assert(peer.shouldPauseData(midSlot, earlyUS, lateUS) == away);
    }
    const uint64_t startAway = anchor + 2 * peer.eawUS;
    const uint64_t resume = startAway + peer.eawUS + lateUS;
    assert(peer.usUntilAway(anchor + peer.eawUS / 2) == 3 * peer.eawUS / 2);
    assert(!peer.shouldPauseData(startAway - earlyUS - 1, earlyUS, lateUS));
    expectScheduledResume(peer, startAway - earlyUS, resume, earlyUS, lateUS);
    expectScheduledResume(peer, startAway + 10000, resume, earlyUS, lateUS);
    memset(sync.channels, 0, sizeof(sync.channels));
    peer.note(sync, anchor, 157);
    assert(!peer.shouldPauseData(anchor, earlyUS, lateUS));
    assert(peer.usUntilAway(anchor) == UINT64_MAX);
    assert(peer.pauseLimitDataUS(anchor, earlyUS, lateUS) == kPeerPauseMaxUS);
}

static void testDataProbe()
{
    using ItlAWDL::PeerDataProbe;
    constexpr uint64_t first = 100000;
    PeerDataProbe probe;
    static_assert(PeerDataProbe::maxInFlight == 4, "Bounded refill burst");
    static_assert(PeerDataProbe::intervalUS == 2000, "2 ms refill interval");
    assert(probe.canRefill(first));
    probe.lastTxUS = first;
    assert(!probe.canRefill(first + 1000));
    assert(probe.canRefill(first + PeerDataProbe::intervalUS));
    probe.lastRxUS = first + 1000;
    assert(probe.canRefill(first + 1100));
    probe.lastTxUS = first + 1100;
    assert(!probe.canRefill(first + 1200));
}

static void testDoorbellBatch()
{
    MtkAwdl::DataTxBatch batch;
    unsigned rings = 0;
    for (unsigned frame = 0; frame < 34; ++frame) {
        if (frame == 15 || frame == 25)
            continue;  // Submission failure never rings or consumes a slot.
        rings += batch.doorbell();
        batch.submitted();
    }
    assert(rings == 2 && !batch.pending);
    for (unsigned i = 0; i < 15; ++i) {
        assert(!batch.doorbell());
        batch.submitted();
    }
    assert(batch.doorbell() && batch.pending == 15); // Busy at the end requires tail flush.
}

using UInt64 = uint64_t;
struct MtkAWDLInterface {
    MtkAwdl::PeerIdentity testPeer;
    uint8_t timingPeer[6] = {};
    uint64_t timingPeerBoundUS = 0;
    unsigned activeChannel = 157, targetFrames = 0, targetSchedules = 0;
    bool windowStatePublished = true;
    ItlAWDL::PeerSchedule peerSchedule = {};
    ItlAWDL::PeerWindowEvidence windowEvidence = {};
    ItlAWDL::PeerPauseState dataPause = {};
    ItlAWDL::PeerDataProbe dataProbe = {};
    struct {
        unsigned channel, frames, schedules;
        uint8_t address[6];
        uint64_t lastScheduleUS, lastFrameUS;
        ItlAWDL::PeerSyncInfo sync;
    } observedPeers[1] = {};
    bool autoTimingAllowed() const;
    void bindTimingPeer(const uint8_t *, uint64_t);
    void publishTimingPeer() {}
    void setProperty(const char *, bool) {}
    void setProperty(const char *, uint64_t, int) {}
    void removeProperty(const char *) {}
    void noteSchedule(const ItlAWDL::PeerSyncInfo &sync, uint64_t now) {
        peerSchedule.note(sync, now, activeChannel);
    }
    void publishWindowState(uint64_t) {}
};

// DRIVER_TIMING_BIND

static void testTimingPeerAndAnnouncements()
{
    MtkAWDLInterface interface;
    const uint8_t old[] = {2, 1, 0, 0, 0, 0}, active[] = {2, 2, 0, 0, 0, 0};
    interface.bindTimingPeer(old, 100000);
    interface.peerSchedule.assumeZero = true;
    interface.peerSchedule.refuted = true;
    interface.peerSchedule.calibrated = true;
    interface.peerSchedule.offset = 5;
    interface.windowEvidence.add(true);
    interface.dataPause.step(true, 100000);
    interface.dataProbe.lastRxUS = 100000;
    interface.bindTimingPeer(active, 200000);
    assert(!memcmp(interface.timingPeer, active, 6) && interface.timingPeerBoundUS == 200000);
    assert(!interface.peerSchedule.valid && interface.peerSchedule.assumeZero &&
        !interface.peerSchedule.refuted && interface.peerSchedule.entryOffset() == 0);
    assert(!interface.windowEvidence.samples && !interface.dataPause.paused && !interface.dataProbe.lastRxUS);
    memcpy(interface.testPeer.address, active, 6);
    interface.bindTimingPeer(old, 300000);
    assert(!memcmp(interface.timingPeer, active, 6));
    assert(!MtkAwdl::idleTimingPeerExpired(3199999, 200000, 3000000));
    assert(MtkAwdl::idleTimingPeerExpired(3200000, 200000, 3000000));
    assert(!MtkAwdl::idleTimingPeerExpired(3300000, 200000, 190000));

    MtkAwdl::AnnouncementSchedule schedule;
    schedule.attempted(false, 1000, false);
    schedule.defer(true, 1000, 450000);
    assert(schedule.due(false, 113640) && !schedule.due(true, 113640));
    schedule.attempted(true, 451000, true);
    assert(schedule.psf == 113640 && schedule.mi == 453000);
    schedule.attempted(false, 451000, false);
    assert(schedule.due(true, 453000) && !schedule.due(false, 453000));
}

int main()
{
    testDoorbellBatch();
    testTimingPeerAndAnnouncements();
    MtkAwdl::RecentDataPeers live;
    const uint8_t mac0[] = {2, 1, 0, 0, 0, 0}, mac1[] = {2, 2, 0, 0, 0, 0};
    assert(!live.recent(mac0, 1234));
    live.note(mac0, 2000000);
    assert(live.recent(mac0, 2149999));
    assert(!live.recent(mac1, 2149999));
    assert(!live.recent(mac0, 2150000));
    assert(live.entries[0].recent(2150000, live.routeGraceUS));
    live.note(mac1, 2100000);
    live.note(mac0, 1999999);
    assert(live.recent(mac0, 2149999) && live.recent(mac1, 2149999));
    assert(!live.entries[0].recent(12000000, live.routeGraceUS));
    MtkAwdl::DataLinkGrace grace;
    assert(!grace.shouldRun(false, true, false, 1000));
    assert(grace.shouldRun(true, true, true, 1100));
    assert(grace.shouldRun(false, true, true, 1200));
    assert(grace.shouldRun(false, true, true, 1200 + grace.durationUS - 1));
    assert(!grace.shouldRun(false, true, true, 1200 + grace.durationUS));
    assert(grace.shouldRun(true, true, false, 1200 + grace.durationUS));
    assert(!grace.shouldRun(false, false, true, 1300 + grace.durationUS));

    MtkAwdl::PeerTxStatus txs;
    constexpr auto status = (2u << 29) | (1u << 25) | (1u << 22) | 0x509;
    constexpr auto pid = uint32_t(MtkAwdl::awdlTxStatusPid) << 24;
    txs.record(status, 15u << 16, pid, 14);
    txs.record(status, 14u << 16, 0, 14);
    assert(!txs.samples && txs.raw == 2 && txs.lastRawWcid == 14 && txs.lastRawPid == 0);
    txs.record(status, 14u << 16, pid, 14);
    assert(txs.samples == 1 && txs.ampdu == 1 && txs.baErrors == 1 && txs.bw == 80 && txs.rate == 0x509);
    testDataPause();
    testSequenceTransition();
    testEquivalentOffsets();
    testDataProbe();
    testIdleSequence();
    uint8_t eth[62] = {};
    eth[0] = 0x33; eth[1] = 0x33; eth[5] = 0xfb; eth[6] = 2;
    eth[12] = 0x86; eth[13] = 0xdd;
    uint8_t *ip = eth + 14;
    ip[0] = 0x60; ip[5] = 8; ip[6] = 17; ip[7] = 255;
    ip[8] = 0xfe; ip[9] = 0x80; ip[23] = 1;
    ip[24] = 0xff; ip[25] = 2; ip[39] = 0xfb;
    ip[40] = ip[42] = 0x14; ip[41] = ip[43] = 0xe9; ip[45] = 8;

    uint8_t frame[128], copy[128];
    size_t written = 0, copied = 0;
    assert(MtkAwdl::buildData(eth, sizeof(eth), 111, frame, sizeof(frame), written));
    ItlAWDL::DataFrameView view;
    assert(ItlAWDL::parseDataFrame(frame, written, false, &view) == ItlAWDL::ParseResult::Valid);
    assert(view.wifiSequence == 111 && view.ip.bytes[46] == 0xd7 && view.ip.bytes[47] == 0x8c);
    assert(ItlAWDL::copyDataEthernet(view, copy, sizeof(copy), &copied) == ItlAWDL::BuildResult::Ready);
    assert(copied == sizeof(eth) && !memcmp(eth, copy, sizeof(eth) - 2));
    assert(!MtkAwdl::buildData(eth, sizeof(eth), 111, frame, 70, written));
    assert(MtkAwdl::buildData(eth, sizeof(eth), 111, frame, sizeof(frame), written, true));
    assert(frame[0] == 0x08 && written == sizeof(eth) + 26);
    eth[0] = 2;
    assert(MtkAwdl::buildData(eth, sizeof(eth), 4095, frame, sizeof(frame), written, true));
    assert(written == sizeof(eth) + 28 && frame[0] == 0x88 && frame[24] == 0 && frame[25] == 0);
    assert(ItlAWDL::parseDataFrame(frame, written, false, &view) == ItlAWDL::ParseResult::Valid);
    assert(view.wifiSequence == 4095 && !memcmp(view.ip.bytes, ip, 46));
    assert(!MtkAwdl::buildData(eth, sizeof(eth), 0, frame, written - 1, copied, true));

    // Verify L4S ECT(1) (TC ECN bits 01 -> ip[1] & 0x30 == 0x10) is cleared to Not-ECT
    // while preserving DSCP, flow label, classic ECT(0), and UDP checksum.
    bool clearedEct1 = false;
    ip[0] = 0x6a; // version 6 + DSCP high bits 0xa
    ip[1] = 0xd5; // DSCP low bits 0b11, ECN = ECT(1) (0x10), flow label high = 0x5
    assert(MtkAwdl::buildData(eth, sizeof(eth), 77, frame, sizeof(frame), written, true, &clearedEct1));
    assert(clearedEct1);
    assert(ItlAWDL::parseDataFrame(frame, written, false, &view) == ItlAWDL::ParseResult::Valid);
    assert(view.ip.bytes[0] == 0x6a && view.ip.bytes[1] == 0xc5);
    assert(view.ip.bytes[46] == 0xd7 && view.ip.bytes[47] == 0x8c);
    ip[1] = 0xe5; // ECN = ECT(0) (0x20) must be preserved
    assert(MtkAwdl::buildData(eth, sizeof(eth), 78, frame, sizeof(frame), written, true, &clearedEct1));
    assert(!clearedEct1);
    assert(ItlAWDL::parseDataFrame(frame, written, false, &view) == ItlAWDL::ParseResult::Valid);
    assert(view.ip.bytes[1] == 0xe5);
    ip[0] = 0x60; ip[1] = 0x00;

    // Verify full 1484-byte AWDL MTU Ethernet frame (14 + 1484 = 1498 bytes) builds cleanly.
    uint8_t fullEth[1498] = {};
    fullEth[0] = 2; fullEth[6] = 2; fullEth[12] = 0x86; fullEth[13] = 0xdd;
    fullEth[14] = 0x60; fullEth[15] = 0x10; // ECT(1)
    fullEth[18] = uint8_t((1444u >> 8) & 0xffu); fullEth[19] = uint8_t(1444u & 0xffu);
    fullEth[20] = 17; fullEth[21] = 64;
    fullEth[22] = 0xfe; fullEth[23] = 0x80; fullEth[37] = 1;
    fullEth[38] = 0xfe; fullEth[39] = 0x80; fullEth[53] = 2;
    fullEth[58] = uint8_t((1444u >> 8) & 0xffu); fullEth[59] = uint8_t(1444u & 0xffu);
    uint8_t fullFrame[2048] = {};
    assert(MtkAwdl::buildData(fullEth, sizeof(fullEth), 99, fullFrame, sizeof(fullFrame), written, true, &clearedEct1));
    assert(clearedEct1 && written == sizeof(fullEth) + 28);
    assert(ItlAWDL::parseDataFrame(fullFrame, written, false, &view) == ItlAWDL::ParseResult::Valid);
    assert((view.ip.bytes[1] & 0x30) == 0);

    ip[45]--;
    assert(!MtkAwdl::buildData(eth, sizeof(eth), 111, frame, sizeof(frame), written));

    ItlAWDL::PeerSchedule peer = {};
    peer.assumeZero = true;
    ItlAWDL::PeerSyncInfo s = {};
    s.awPeriodTU = 16; s.downCounterTU = 64; s.channels[0] = 36; s.channels[1] = 149;
    peer.note(s, 100000, 36);
    assert(peer.inPresentAwStart(101000, 4500));
    assert(!peer.inPresentAwStart(108000, 4500));
    assert(!peer.inPresentAwStart(166000, 4500));
    assert(!peer.inPresentAwStart(2200000, 4500));
    using Update = ItlAWDL::PeerSchedule::Update;
    assert(peer.note(s, 101024, 36) == Update::Stable);
    assert(peer.phaseErrorUS == 1024 && peer.anchorEndUS == 165792);
    assert(peer.note(s, 101024 + ItlAWDL::kPeerScheduleStaleUS, 36) == Update::Gap);
    s.channels[0] = 149;
    assert(peer.note(s, 101025 + ItlAWDL::kPeerScheduleStaleUS, 36) == Update::Sequence);
    assert(peer.sequenceChanges == 1 && peer.presentEntries() == 0);
    assert(peer.note(s, 121025 + ItlAWDL::kPeerScheduleStaleUS, 36) == Update::Phase);

    ItlAWDL::PeerSchedule wrapped = {};
    s.awCounter = 65532;
    s.downCounterTU = 1;
    wrapped.note(s, 100000, 149);
    s.awCounter = 0;
    s.downCounterTU = 63;
    assert(wrapped.note(s, 102048, 149) == Update::Stable);
    assert(wrapped.phaseErrorUS == 0);

    ItlAWDL::PeerWindowEvidence history;
    for (int i = 0; i < 7; ++i) history.add(true);
    assert(!history.reliable());
    history.add(true);
    assert(history.reliable());
    for (int i = 0; i < 32; ++i) history.add(false);
    assert(history.samples == 32 && history.matches() == 0 && !history.reliable());
    for (int i = 0; i < 24; ++i) history.add(true);
    assert(history.samples == 32 && history.matches() == 24 && history.reliable());
}
"""
with tempfile.TemporaryDirectory(prefix="mtk-awdl-d16-test-") as path:
    source = Path(path, "test.cpp")
    exe = Path(path, "test")
    driver = (root / "AirportMtkWlan/MtkAwdlInterface.cpp").read_text()
    policy = driver.split("bool MtkAWDLInterface::autoTimingAllowed()", 1)[1].split(
        "const uint8_t *MtkAWDLInterface::queuedUnicastPeer", 1)[0]
    bind = driver.split("void MtkAWDLInterface::bindTimingPeer(", 1)[1].split(
        "void MtkAWDLInterface::reviewPeers", 1)[0]
    source.write_text(body.replace("// DRIVER_TIMING_BIND", "bool MtkAWDLInterface::autoTimingAllowed()" +
                                  policy + "void MtkAWDLInterface::bindTimingPeer(" + bind))
    subprocess.run(["clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", "-I", str(root / "include"),
                    str(source), "-o", str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
