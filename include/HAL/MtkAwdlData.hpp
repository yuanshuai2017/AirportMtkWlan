// AWDL IPv6 transport framing. Framing follows ForbiddenItlwm
// (GPL-2.0); this layer does not own Skywalk packets or radio descriptors.
#pragma once
#include "Awdl/AWDLDataFrame.hpp"

namespace MtkAwdl {

template <size_t Capacity>
struct DataPeerActivity {
    static constexpr uint64_t probeGraceUS = 150000;
    static constexpr uint64_t routeGraceUS = 10000000;
    struct Entry {
        uint8_t mac[6] = {};
        uint64_t lastActiveDataUS = 0;

        bool recent(uint64_t now, uint64_t limit) const {
            return lastActiveDataUS && now >= lastActiveDataUS && now - lastActiveDataUS < limit;
        }
    } entries[Capacity];

    void note(const uint8_t *mac, uint64_t timestamp) {
        constexpr uint8_t zero[6] = {};
        if (!timestamp || (mac[0] & 1) || !memcmp(mac, zero, 6))
            return;
        auto *oldest = &entries[0];
        for (auto &peer : entries) {
            if (peer.lastActiveDataUS && !memcmp(mac, peer.mac, 6)) {
                if (timestamp > peer.lastActiveDataUS)
                    peer.lastActiveDataUS = timestamp;
                return;
            }
            if (peer.lastActiveDataUS < oldest->lastActiveDataUS)
                oldest = &peer;
        }
        if (timestamp > oldest->lastActiveDataUS) {
            memcpy(oldest->mac, mac, 6);
            oldest->lastActiveDataUS = timestamp;
        }
    }

    uint64_t lastActive(const uint8_t *mac) const {
        for (const auto &peer : entries)
            if (peer.lastActiveDataUS && !memcmp(mac, peer.mac, 6))
                return peer.lastActiveDataUS;
        return 0;
    }

    bool recent(const uint8_t *mac, uint64_t now) const {
        for (const auto &peer : entries)
            if (peer.recent(now, probeGraceUS) && !memcmp(mac, peer.mac, 6))
                return true;
        return false;
    }
};

using RecentDataPeers = DataPeerActivity<2>;

// Preserve the Skywalk link across a brief radio interruption. The channel
// gate still blocks RF submission while there is no permitted channel.
struct DataLinkGrace {
    static constexpr uint64_t durationUS = 1000000;
    uint64_t unavailableSinceUS = 0;

    bool shouldRun(bool channel, bool syncEnabled, bool running, uint64_t now) {
        if (channel || !syncEnabled || !running)
            unavailableSinceUS = 0;
        else if (!unavailableSinceUS)
            unavailableSinceUS = now;
        return syncEnabled && (channel || (running && now >= unavailableSinceUS &&
            now - unavailableSinceUS < durationUS));
    }
};

constexpr size_t ethernetMax = 1514;

inline bool linkLocal(const uint8_t *ip)
{
    return ip[0] == 0xfe && (ip[1] & 0xc0) == 0x80;
}

// The experimental link carries only directly connected IPv6, with either a
// link-local unicast destination or interface/link-local multicast.
inline bool localTraffic(const uint8_t *ip, size_t length)
{
    return ItlAWDL::validIPv6Payload(ip, length) && linkLocal(ip + 8) &&
        (linkLocal(ip + 24) || (ip[24] == 0xff && (ip[25] & 15) <= 2));
}

inline bool finalizeChecksum(uint8_t *ip, size_t total)
{
    if (!localTraffic(ip, total))
        return false;
    const size_t length = total - 40;
    uint8_t *const payload = ip + 40;
    size_t field;
    switch (ip[6]) {
    case 6:
        if (length < 20 || (payload[12] >> 4) < 5 || size_t(payload[12] >> 4) * 4 > length)
            return false;
        field = 16;
        break;
    case 17:
        if (length < 8 || ((size_t(payload[4]) << 8) | payload[5]) != length)
            return false;
        field = 6;
        break;
    case 58:
        if (length < 4)
            return false;
        field = 2;
        break;
    default:
        return false;
    }

    payload[field] = payload[field + 1] = 0;
    uint32_t sum = uint32_t(length) + ip[6];
    for (size_t i = 8; i < 40; i += 2)
        sum += (uint32_t(ip[i]) << 8) | ip[i + 1];
    for (size_t i = 0; i < length; i += 2)
        sum += (uint32_t(payload[i]) << 8) | (i + 1 < length ? payload[i + 1] : 0);
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    const uint16_t check = uint16_t(~sum);
    const uint16_t wire = !check && ip[6] == 17 ? 0xffff : check;
    payload[field] = uint8_t(wire >> 8);
    payload[field + 1] = uint8_t(wire);
    return true;
}

// macOS Tahoe x86_64 AirDrop uses BSD socket-flow without kernel tx_time
// pacing. Clearing L4S ECT(1) on direct P2P TX prevents libquic from enabling
// its unpaced L4S pacer (which drifts sent_time seconds into the future and
// freezes PTO loss recovery).
inline bool clearL4sEct1(uint8_t *ip, size_t total)
{
    if (!ip || total < 40 || (ip[0] >> 4) != 6 || (ip[1] & 0x30) != 0x10)
        return false;
    ip[1] &= static_cast<uint8_t>(~0x30u);
    return true;
}

inline bool buildData(const uint8_t *ethernet, size_t length, uint16_t sequence,
                      uint8_t *output, size_t capacity, size_t &written,
                      bool qos = false, bool *clearedEct1 = nullptr)
{
    constexpr uint8_t bssid[] = {0, 0x25, 0, 0xff, 0x94, 0x73};
    if (clearedEct1)
        *clearedEct1 = false;
    if (length < 54 || length > ethernetMax)
        return false;
    qos = qos && !(ethernet[0] & 1);
    const size_t headerLength = qos ? 26 : 24;
    if (capacity < length + headerLength + 2 ||
        ethernet[12] != 0x86 || ethernet[13] != 0xdd)
        return false;
    size_t payloadLength = 0;
    if (ItlAWDL::buildIPv6DataPayload(ethernet + 14, length - 14, sequence,
            output + headerLength, capacity - headerLength, &payloadLength) != ItlAWDL::BuildResult::Ready ||
        !finalizeChecksum(output + headerLength + 16, payloadLength - 16))
        return false;
    const bool cleared = clearL4sEct1(output + headerLength + 16, payloadLength - 16);
    if (clearedEct1)
        *clearedEct1 = cleared;
    for (size_t i = 0; i < headerLength; ++i)
        output[i] = 0;
    output[0] = qos ? 0x88 : 0x08;
    for (size_t i = 0; i < 6; ++i) {
        output[4 + i] = ethernet[i];
        output[10 + i] = ethernet[6 + i];
        output[16 + i] = bssid[i];
    }
    ItlAWDL::write16(output + 22, uint16_t((sequence & 4095) << 4));
    written = headerLength + payloadLength;
    return true;
}
}
