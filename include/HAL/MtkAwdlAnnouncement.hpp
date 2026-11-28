// Fixed-channel announcement construction, based on ForbiddenItlwm (GPL-2.0).
#pragma once
#include "MtkAwdlBa.hpp"
#include "MtkAwdlActionFrame.hpp"
#include "MtkAwdlData.hpp"
#include "Awdl/AWDLLocalSchedule.hpp"
#include "Awdl/AWDLPeerSchedule.hpp"
#include "MtkAwdlServiceRecord.hpp"

namespace MtkAwdl {
constexpr size_t announcementTemplateMax = 0x724;
constexpr size_t masterIndicationMax = 1200;

struct ServiceSummary {
    uint32_t records = 0;
    uint32_t airDropPtrs = 0;
    uint32_t airDropOtherTypes = 0;
    uint32_t airDropBadLengths = 0;
    uint32_t airDropBadTargets = 0;
    uint32_t airDropShortTargets = 0;
    uint32_t airDropCorroborated = 0;
    uint32_t airDropTargetBytes = 0;
    uint32_t airDropTargetLabelBytes = 0;
    uint32_t serviceUnknownLayouts = 0;
    uint32_t airDropOtherHints = 0;
    bool airDrop = false;

    void add(uint8_t type, const uint8_t *body, size_t length)
    {
        records += type == 2 && length != 0;
        if (type == 2) {
            const auto result = inspectAirDropPtr(body, length);
            airDropPtrs += result == PtrResult::Valid;
            airDropOtherTypes += result == PtrResult::WrongType;
            airDropBadLengths += result == PtrResult::BadLength;
            airDropBadTargets += result == PtrResult::BadTarget;
            serviceUnknownLayouts += result == PtrResult::UnknownLayout;
            airDropOtherHints += (result == PtrResult::Other || result == PtrResult::UnknownLayout) &&
                hasAirDropNameHint(body, length);
        }
        // Tahoe's AirDrop availability attribute (version, flags).
        airDrop |= type == 35 && length == 2 && body[0] == 1 && body[1] != 0;
    }

    bool advertisesService() const { return records != 0 || airDrop; }
};

inline void inspectShortAirDropTargets(const uint8_t *tlvs, size_t length, ServiceSummary &summary)
{
    if (!summary.airDropBadTargets)
        return;
    // The caller has already validated the entire TLV sequence.
    for (size_t offset = 0; offset < length;) {
        const auto *record = tlvs + offset;
        const size_t bytes = ItlAWDL::read16(record + 1);
        if (record[0] == 2 && inspectAirDropPtr(record + 3, bytes) == PtrResult::BadTarget) {
            ServiceName owner, target;
            uint8_t type = 0;
            if (serviceRecord(record + 3, bytes, owner, type, target)) {
                const size_t label = instanceLabel(target);
                summary.airDropTargetBytes = uint32_t(target.length);
                summary.airDropTargetLabelBytes = uint32_t(label);
                if (label && shortInstanceName(target, label)) {
                    ++summary.airDropShortTargets;
                    if (corroboratedAirDropTarget(target, tlvs, length)) {
                        ++summary.airDropCorroborated;
                        ++summary.airDropPtrs;
                        --summary.airDropBadTargets;
                    }
                }
            }
        }
        offset += bytes + 3;
    }
}

inline bool inspectMasterIndication(const uint8_t *bytes, size_t length, ServiceSummary &result)
{
    if (!bytes || !length || length > masterIndicationMax)
        return false;
    ServiceSummary services;
    bool election = false;
    for (size_t offset = 0; offset < length;) {
        if (length - offset < 3)
            return false;
        const uint8_t type = bytes[offset];
        const size_t bodyLength = ItlAWDL::read16(bytes + offset + 1);
        if (bodyLength > length - offset - 3)
            return false;
        election |= type == 24 && bodyLength >= 28;
        services.add(type, bytes + offset + 3, bodyLength);
        offset += 3 + bodyLength;
    }
    if (!election)
        return false;
    inspectShortAirDropTargets(bytes, length, services);
    result = services;
    return true;
}

enum class TxKind : uint8_t { Sync, Service, VerifiedService, Data, GroupData, DataBaEligible };

struct AnnouncementSchedule {
    uint64_t psf = 0;
    uint64_t mi = 0;

    bool due(bool master, uint64_t now) const { return now >= (master ? mi : psf); }
    void defer(bool master, uint64_t now, uint64_t delay) { (master ? mi : psf) = now + delay; }
    void attempted(bool master, uint64_t now, bool busy) {
        defer(master, now, busy ? 2000 : master ? 225280 : 112640);
    }
};

// Matches the normal PCIe TX burst. Failed submissions do not ring or
// consume a slot, so the caller flushes any tail after the loop exits.
struct DataTxBatch {
    unsigned pending = 0;

    bool doorbell() const { return pending == 15; }
    void submitted() { pending = doorbell() ? 0 : pending + 1; }
};

// MT7921 PCIe TXS has two header dwords and eight dwords per report.
constexpr uint8_t awdlTxStatusPid = 0x7e;
struct PeerTxStatus {
    uint32_t raw = 0;
    uint16_t lastRawWcid = 0;
    uint8_t lastRawPid = 0;
    uint32_t samples = 0;
    uint32_t ampdu = 0;
    uint32_t baErrors = 0;
    uint16_t rate = 0;
    uint8_t bw = 0;

    void record(uint32_t txs0, uint32_t txs2, uint32_t txs3, uint16_t wcid) {
        ++raw;
        lastRawWcid = (txs2 >> 16) & 0x3ff;
        lastRawPid = (txs3 >> 24) & 0xff;
        if (lastRawWcid != wcid || lastRawPid != awdlTxStatusPid)
            return;
        ++samples;
        ampdu += bool(txs0 & (1u << 25));
        baErrors += bool(txs0 & (1u << 22));
        rate = txs0 & 0x3fff;
        bw = uint8_t(20u << ((txs0 >> 29) & 3));
    }

    bool operator==(const PeerTxStatus &other) const {
        return raw == other.raw && lastRawWcid == other.lastRawWcid && lastRawPid == other.lastRawPid &&
            samples == other.samples && ampdu == other.ampdu && baErrors == other.baErrors &&
            rate == other.rate && bw == other.bw;
    }
};

constexpr unsigned awdlPeerObservationLimit = 8;
using UnicastAcks = DataPeerActivity<awdlPeerObservationLimit>;

struct AnnouncementCompletions {
    uint32_t sent = 0;
    uint32_t failed = 0;
    uint32_t serviceSent = 0;
    uint32_t serviceFailed = 0;
    uint32_t lastStatus = 0;
    uint32_t verifiedServiceSent = 0;
    uint32_t verifiedCompletionLastUS = 0;
    uint32_t verifiedCompletionMaxUS = 0;
    uint32_t dataSent = 0;
    uint32_t dataFailed = 0;
    UnicastAcks unicastAcks;
    uint32_t unicastReportedSent = 0;
    uint32_t unicastReportedFailed = 0;
    uint32_t unicastLastFailStatus = 0;
    uint32_t peerTxSampleRequests = 0;
    uint32_t peerAggTxSent = 0;
    uint32_t peerAggTxFailed = 0;
    uint8_t peerAggLastStatus = 0;
    uint32_t bgScanDeferred = 0;
    uint8_t peerWtblProfile = 0;
    uint8_t peerMaxBw = 80;
    uint8_t peerCapMask = 0;
    bool peerMatchingSco = false;
    bool peerTwoStage = false;
    uint32_t peerTuneGen = 0;
    uint32_t dataInFlight = 0;
    uint8_t txRateIdx = 0;
    uint8_t peerBw = 20;
    bool peerFixedBa = false;
    PeerTxStatus peerTxStatus;
    uint16_t peerWcid = 0;
    bool peerWcidActive = false;
    uint64_t peerLastDataAckUS = 0;
    uint8_t peerMac[6] = {};
    PeerBaState peerBaState = PeerBaState::Idle;
    uint16_t peerBaWinSize = 0;
    uint32_t peerBaReqSent = 0;
    uint32_t peerBaReqAcked = 0;
    uint32_t peerBaReqFailed = 0;
    uint32_t peerBaRxAny = 0;
    uint32_t peerBaRxReq = 0;
    uint16_t peerBaRxTidMask = 0;
    uint8_t peerBaRxActiveTidMask = 0;
    uint32_t peerBaRxReconfigs = 0;
    uint32_t peerBaRxOtherTid = 0;
    bool peerRxBaEnabled = true;
    uint32_t peerBaRxRespSent = 0;
    uint32_t peerBaRxRejected = 0;
    uint32_t peerBaRxRejectFilter = 0;
    uint32_t peerBaRxRejectResponder = 0;
    uint32_t peerBaRxLastStatus = 0;
    uint32_t peerBaRespOk = 0;
    uint32_t peerBaDelba = 0;
    uint32_t peerBaErrors = 0;
    uint32_t peerBaLastError = 0;
    uint32_t peerWcidErrors = 0;
    uint32_t peerWcidLastError = 0;
    uint8_t peerWcidFailStep = 0;
};

struct PeerTuneRequest {
    bool setFixedBa = false;
    bool fixedBa = false;
    bool setMaxBw = false;
    uint8_t maxBw = 80;
    bool setCapMask = false;
    uint8_t capMask = 0;
    bool setMatchingSco = false;
    bool matchingSco = false;
    bool setTwoStage = false;
    bool twoStage = false;
    bool resetStats = true;
};

constexpr uint32_t electionMetric = 60;
constexpr uint32_t electionCounter = 1;
constexpr unsigned electionMaxHops = 10;
constexpr unsigned syncTreeCapacity = electionMaxHops + 1;
constexpr size_t electionV2Length = 40;

struct PeerElection {
    uint8_t master[6] = {};
    uint8_t peer[6] = {};
    uint32_t metric = 0;
    uint32_t counter = electionCounter;
    uint32_t hops = 0;
    uint64_t heardUS = 0;
    bool hasCounter = false;
    uint8_t tree[syncTreeCapacity][6] = {};
    unsigned treeSize = 0;
};

inline bool electionAddress(const uint8_t *mac) {
    constexpr uint8_t zero[6] = {};
    return !(mac[0] & 1) && memcmp(mac, zero, 6);
}

// OWL frame.h and Wireshark packet-awdl.c. Both versions encode metrics
// little-endian, but v1 has an 8-bit hop count and no public RLFC/SLFC.
inline bool parsePeerElection(const uint8_t *frame, size_t length, uint64_t now, PeerElection &out) {
    if (!frame || length < 40 || !electionAddress(frame + 10))
        return false;
    PeerElection candidate;
    memcpy(candidate.peer, frame + 10, 6);
    for (size_t offset = 40; offset < length;) {
        if (length - offset < 3)
            return false;
        const auto *value = frame + offset + 3;
        const size_t size = ItlAWDL::read16(value - 2);
        if (size > length - offset - 3)
            return false;
        if (frame[offset] == 24 && size >= 28 && electionAddress(value)) {
            memcpy(candidate.master, value, 6);
            candidate.metric = ItlAWDL::read32(value + 20);
            candidate.counter = ItlAWDL::read32(value + 12);
            candidate.hops = ItlAWDL::read32(value + 16);
            candidate.hasCounter = true;
        } else if (frame[offset] == 5 && !candidate.hasCounter && size >= 19 &&
                   electionAddress(value + 5)) {
            memcpy(candidate.master, value + 5, 6);
            candidate.metric = ItlAWDL::read32(value + 11);
            candidate.hops = value[3];
        } else if (frame[offset] == 20 && size && size % 6 == 0 && size / 6 < syncTreeCapacity) {
            candidate.treeSize = unsigned(size / 6);
            memcpy(candidate.tree, value, size);
        }
        offset += 3 + size;
    }
    if (!electionAddress(candidate.master) || !candidate.metric || candidate.hops >= electionMaxHops)
        return false;
    candidate.heardUS = now;
    out = candidate;
    return true;
}

struct AnnouncementTiming {
    const PeerElection *peer = nullptr;
    const ItlAWDL::PeerSchedule *clock = nullptr;
    const ItlAWDL::PeerSyncInfo *sync = nullptr;
    uint64_t localEpochUS = 0;
};

struct AdvertisedElection {
    bool following = false;
    uint8_t master[6] = {};
    uint32_t counter = electionCounter;
    uint32_t hops = 0;
};

constexpr uint64_t nativeKeepaliveIntervalUS = 2000000;
constexpr size_t nativeKeepaliveActionMax = 768;

inline bool nativeKeepaliveDue(uint64_t now, uint64_t lastFrameUS, uint64_t lastKeepaliveUS,
                               uint64_t lastDataAckUS, uint64_t lastDataRxUS) {
    const auto activity = lastDataAckUS > lastDataRxUS ? lastDataAckUS : lastDataRxUS;
    return activity && now >= activity && now - activity < nativeKeepaliveIntervalUS &&
        lastFrameUS && now >= lastFrameUS && now - lastFrameUS >= nativeKeepaliveIntervalUS &&
        (!lastKeepaliveUS || (now >= lastKeepaliveUS && now - lastKeepaliveUS >= nativeKeepaliveIntervalUS));
}

// Refresh an FCS-free, validated Action for the native management receiver.
inline bool refreshNativeAction(const uint8_t *frame, size_t length, uint64_t elapsedUS,
                                uint16_t previousSeq, uint8_t *output, size_t capacity) {
    using namespace ItlAWDL;
    if (!output || !length || length > capacity || length > nativeKeepaliveActionMax ||
        actionFrameLength(frame, length) != length)
        return false;
    memcpy(output, frame, length);
    write16(output + 22, uint16_t(((previousSeq + 1) & 0xfff) << 4));
    write32(output + 32, read32(frame + 32) + uint32_t(elapsedUS));
    write32(output + 36, read32(frame + 36) + uint32_t(elapsedUS));
    for (size_t offset = minimumFrameLength; offset < length;) {
        const size_t size = read16(frame + offset + 1);
        if (frame[offset] == 4 && size >= 31) {
            auto *sync = output + offset + 3;
            const unsigned period = read16(sync + 5);
            const unsigned presence = sync[27];
            const unsigned extended = period * presence;
            const unsigned down = read16(sync + 1);
            if (period < 8 || period > 64 || !presence || presence > 4 || down > extended)
                return false;
            const uint64_t advancedTU = extended - down + elapsedUS / 1024;
            const unsigned phase = unsigned(advancedTU % extended);
            const unsigned common = read16(sync + 13);
            const unsigned aw = read16(sync + 29);
            write16(sync + 29, uint16_t(aw - aw % presence + advancedTU / period));
            write16(sync + 1, uint16_t(extended - phase));
            write16(sync + 15, uint16_t(common > phase ? common - phase : 0));
            break;
        }
        offset += 3 + size;
    }
    return true;
}

inline bool buildAnnouncement(const uint8_t *source, uint8_t channel, uint16_t sequence, uint64_t nowUS,
                              const uint8_t *nativeTemplate, size_t nativeLength,
                              uint8_t *tlvs, size_t tlvCapacity, uint8_t *output,
                              size_t outputCapacity, size_t *written, ServiceSummary *services, bool masterIndication,
                              const AnnouncementTiming &timing = {}, AdvertisedElection *advertised = nullptr)
{
    const uint8_t channelClass = ItlAWDL::globalOperatingClass20(channel);
    if (!channelClass || !source || !nativeTemplate || !nativeLength || nativeLength > announcementTemplateMax ||
        !tlvs || tlvCapacity < 44 || !output || !written || !services)
        return false;
    AdvertisedElection election;
    memcpy(election.master, source, 6);
    const auto *peer = timing.peer;
    bool loop = false;
    if (peer && peer->treeSize < syncTreeCapacity)
        for (unsigned i = 0; i < peer->treeSize; ++i)
            loop |= !memcmp(source, peer->tree[i], 6);
    if (peer && peer->heardUS && nowUS >= peer->heardUS &&
        nowUS - peer->heardUS < ItlAWDL::kPeerScheduleStaleUS && peer->metric &&
        peer->hops < electionMaxHops && !loop && electionAddress(peer->master) &&
        electionAddress(peer->peer) && memcmp(source, peer->master, 6) && memcmp(source, peer->peer, 6)) {
        election.following = true;
        memcpy(election.master, peer->master, 6);
        election.counter = peer->counter;
        election.hops = peer->hops + 1;
    }
    tlvs[0] = 18;
    ItlAWDL::write16(tlvs + 1, 41);
    constexpr uint8_t header[] = {15, 3, 0, 3, 0xff, 0xff};
    memcpy(tlvs + 3, header, sizeof(header));
    for (unsigned i = 0; i < 16; ++i) {
        tlvs[9 + i * 2] = channel;
        tlvs[10 + i * 2] = channelClass;
    }
    memset(tlvs + 41, 0, 3);  // TLV 18's trailing padding.
    size_t used = 44;
    ServiceSummary summary;
    for (size_t offset = 0; offset < nativeLength;) {
        if (nativeLength - offset < 3)
            return false;
        const uint8_t type = nativeTemplate[offset];
        const size_t length = size_t(ItlAWDL::read16(nativeTemplate + offset + 1)) + 3;
        if (length > nativeLength - offset)
            return false;
        if (type != 4 && type != 5 && type != 18 && type != 20 && type != 24) {
            if (length > tlvCapacity - used)
                return false;
            for (size_t i = 0; i < length; ++i)
                tlvs[used + i] = nativeTemplate[offset + i];
            used += length;
            summary.add(type, nativeTemplate + offset + 3, length - 3);
        }
        offset += length;
    }

    uint8_t tree[syncTreeCapacity][6] = {};
    unsigned treeSize = 0;
    const auto addNode = [&](const uint8_t *mac) {
        for (unsigned i = 0; i < treeSize; ++i)
            if (!memcmp(tree[i], mac, 6))
                return;
        memcpy(tree[treeSize++], mac, 6);
    };
    if (election.following) {
        addNode(election.master);
        // Validate the root of the received path. Keep space for the parent
        // and ourselves even when the peer sends the longest allowed path.
        if (peer->treeSize == peer->hops + 1 && peer->treeSize < syncTreeCapacity &&
            !memcmp(peer->tree[0], election.master, 6) &&
            !memcmp(peer->tree[peer->treeSize - 1], peer->peer, 6)) {
            for (unsigned i = 1; i + 1 < peer->treeSize; ++i)
                if (electionAddress(peer->tree[i]) && memcmp(peer->tree[i], peer->peer, 6))
                    addNode(peer->tree[i]);
        }
        addNode(peer->peer);
    }
    addNode(source);
    if (tlvCapacity - used < 3 + electionV2Length + 3 + treeSize * 6)
        return false;
    tlvs[used] = 24;
    ItlAWDL::write16(tlvs + used + 1, electionV2Length);
    auto *value = tlvs + used + 3;
    memset(value, 0, electionV2Length);
    memcpy(value, election.master, 6);
    memcpy(value + 6, election.following ? peer->peer : source, 6);
    ItlAWDL::write32(value + 12, election.counter);
    ItlAWDL::write32(value + 16, election.hops);
    ItlAWDL::write32(value + 20, election.following ? peer->metric : electionMetric);
    ItlAWDL::write32(value + 24, electionMetric);
    ItlAWDL::write32(value + 36, electionCounter);
    used += 3 + electionV2Length;
    tlvs[used] = 20;
    ItlAWDL::write16(tlvs + used + 1, treeSize * 6);
    memcpy(tlvs + used + 3, tree, treeSize * 6);
    used += 3 + treeSize * 6;

    ItlAWDL::SyncPrefix schedule = {channel, channel, 0,
        0, 16, 110, 0x1000, 16, 16, 0, 3, 3, 3, 3, {}};
    memcpy(schedule.master, election.master, 6);
    uint8_t sync[73];
    size_t syncLength = 0;
    ItlAWDL::BuildResult syncResult;
    if (election.following && timing.sync && timing.sync->masterChannel)
        schedule.masterChannel = timing.sync->masterChannel;
    if (election.following && timing.clock && timing.sync && timing.clock->awUS() &&
        timing.clock->fresh(nowUS) && !memcmp(timing.sync->master, election.master, 6)) {
        const auto awUS = timing.clock->awUS();
        uint64_t into;
        const auto eaw = timing.clock->eawAt(nowUS, &into);
        schedule.awPeriod = uint16_t(awUS / 1024);
        schedule.commonLength = timing.sync->awCommonTU;
        schedule.extensionLength = timing.sync->awExtTU;
        schedule.txDownCounter = uint16_t((timing.clock->eawUS - into + 1023) / 1024);
        const auto phaseTU = into / 1024;
        schedule.remainingAW = phaseTU < schedule.commonLength ? uint16_t(schedule.commonLength - phaseTU) : 0;
        const auto counter = uint16_t(eaw * 4u + into / awUS);
        syncResult = ItlAWDL::buildFixedScheduleAt(schedule, counter, sync, sizeof(sync), &syncLength);
    } else {
        const auto masterChannel = schedule.masterChannel;
        schedule.masterChannel = channel;
        syncResult = ItlAWDL::buildLocalFixedSchedule(schedule, timing.localEpochUS, nowUS, 0,
                                                      sync, sizeof(sync), &syncLength);
        if (syncResult == ItlAWDL::BuildResult::Ready)
            sync[3] = masterChannel;
    }
    if (syncResult != ItlAWDL::BuildResult::Ready)
        return false;
    ItlAWDL::LocalFrame frame = {{}, {255, 255, 255, 255, 255, 255},
        uint8_t(masterIndication ? 3 : 0), uint16_t(sequence & 4095),
        uint32_t(nowUS), uint32_t(nowUS), sync, syncLength, tlvs, used};
    for (unsigned i = 0; i < 6; ++i)
        frame.source[i] = source[i];
    if (ItlAWDL::buildLocalFrame(frame, output, outputCapacity, written) != ItlAWDL::BuildResult::Ready)
        return false;
    inspectShortAirDropTargets(tlvs, used, summary);
    *services = summary;
    if (advertised)
        *advertised = election;
    return true;
}
}
