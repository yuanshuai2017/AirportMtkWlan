#pragma once

#include <string.h>
#include "Awdl/AWDLFrameBuilder.hpp"

namespace MtkAwdl {

enum class PeerBaState : uint8_t { Idle, Requested, Active, Failed, Disabled };

constexpr uint8_t baCategory = 3;
constexpr uint8_t baRequest = 0, baResponse = 1, baDelba = 2;
constexpr uint16_t baWindow = 64;
constexpr uint16_t baImmediate = 1u << 1;
constexpr uint16_t baWindowMask = 0xffc0;
constexpr uint16_t baTidMask = 0x003c;
constexpr uint16_t delbaInitiator = 1u << 11;
constexpr size_t baRequestLength = 33, baDelbaLength = 30;
constexpr uint8_t awdlBssid[6] = {0, 0x25, 0, 0xff, 0x94, 0x73};

inline void buildBaHeader(uint8_t *frame, size_t length, const uint8_t *source,
                          const uint8_t *peer, uint8_t action) {
    memset(frame, 0, length);
    frame[0] = 0xd0;  // Management Action.
    memcpy(frame + 4, peer, 6);
    memcpy(frame + 10, source, 6);
    memcpy(frame + 16, awdlBssid, 6);
    frame[24] = baCategory;
    frame[25] = action;
}

inline void buildBaRequest(uint8_t (&frame)[baRequestLength], const uint8_t *source,
                           const uint8_t *peer, uint8_t token, uint16_t ssn) {
    buildBaHeader(frame, sizeof(frame), source, peer, baRequest);
    frame[26] = token;
    ItlAWDL::write16(frame + 27, (baWindow << 6) | baImmediate);
    ItlAWDL::write16(frame + 31, (ssn & 0xfff) << 4);
}

inline void buildDelba(uint8_t (&frame)[baDelbaLength], const uint8_t *source,
                       const uint8_t *peer) {
    buildBaHeader(frame, sizeof(frame), source, peer, baDelba);
    ItlAWDL::write16(frame + 26, delbaInitiator);
    ItlAWDL::write16(frame + 28, 37);  // QSTA leaving the BA agreement.
}

inline bool baRequestWindow(bool present, uint64_t now, uint64_t lastPeerRx) {
    constexpr uint64_t recentRxUS = 20000;
    return present && lastPeerRx && now >= lastPeerRx && now - lastPeerRx <= recentRxUS;
}

inline bool isPeerBaAction(const uint8_t *frame, size_t length, const uint8_t *local,
                           const uint8_t *peer) {
    // The peer MAC is also the BSSID configured for our AWDL firmware slot.
    return length >= 26 && frame[0] == 0xd0 && !(frame[1] & 0xc7) &&
        !(frame[22] & 0xf) && frame[24] == baCategory &&
        !memcmp(frame + 4, local, 6) && !memcmp(frame + 10, peer, 6) &&
        (!memcmp(frame + 16, awdlBssid, 6) || !memcmp(frame + 16, peer, 6));
}

struct BaRequest {
    uint8_t token;
    uint8_t tid;
    uint16_t ssn;
    uint16_t window;
    bool immediate;
    bool peerBssid;
};

inline bool parseBaRequest(const uint8_t *frame, size_t length, BaRequest &request) {
    if (length < baRequestLength || frame[24] != baCategory || frame[25] != baRequest)
        return false;
    const uint16_t params = ItlAWDL::read16(frame + 27);
    const uint16_t start = ItlAWDL::read16(frame + 31);
    if (start & 0xf)
        return false;
    const uint16_t window = (params & baWindowMask) >> 6;
    request = {frame[26], uint8_t((params & baTidMask) >> 2), uint16_t(start >> 4),
        window && window < baWindow ? window : baWindow, bool(params & baImmediate),
        !memcmp(frame + 16, frame + 10, 6)};
    return true;
}

inline void buildBaResponse(uint8_t (&frame)[baRequestLength], const uint8_t *source,
                            const uint8_t *peer, BaRequest request, uint16_t status) {
    buildBaHeader(frame, sizeof(frame), source, peer, baResponse);
    if (request.peerBssid)
        memcpy(frame + 16, peer, 6);
    frame[26] = request.token;
    ItlAWDL::write16(frame + 27, status);
    ItlAWDL::write16(frame + 29, (request.window << 6) | (request.tid << 2) | baImmediate);
}

inline bool parseOriginatorDelba(const uint8_t *frame, size_t length, uint8_t &tid) {
    if (length < baDelbaLength || frame[24] != baCategory || frame[25] != baDelba)
        return false;
    const uint16_t params = ItlAWDL::read16(frame + 26);
    tid = params >> 12;
    return params & delbaInitiator;
}

inline bool parseBar(const uint8_t *frame, size_t length, uint8_t &tid, uint16_t &ssn) {
    if (length < 20 || frame[0] != 0x84)
        return false;
    const auto control = ItlAWDL::read16(frame + 16);
    const auto start = ItlAWDL::read16(frame + 18);
    if ((control & 0x0006) != 0x0004 || (start & 0xf))
        return false;  // Only single-TID compressed BAR.
    tid = control >> 12;
    ssn = start >> 4;
    return true;
}

// The MCU sends Block Ack. The host still orders the MPDUs before feeding
// Skywalk, including a finite wait for a missing MPDU or a lost BAR.
template <typename Packet>
struct RxReorder {
    static constexpr uint64_t gapTimeoutUS = 40000;
    Packet frames[baWindow] = {};
    uint16_t head = 0, window = 0, queued = 0;
    uint64_t gapSince = 0;

    static uint16_t distance(uint16_t sn, uint16_t from) { return (sn - from) & 0xfff; }

    template <typename Deliver>
    void advance(uint16_t next, Deliver deliver) {
        unsigned steps = distance(next, head);
        if (steps >= 2048)
            return;
        for (; steps && queued; --steps) {
            auto &entry = frames[head % baWindow];
            if (entry) {
                auto packet = entry;
                entry = {};
                --queued;
                deliver(packet);
            }
            head = (head + 1) & 0xfff;
        }
        head = next;
    }

    template <typename Deliver>
    void contiguous(uint64_t now, Deliver deliver) {
        while (frames[head % baWindow])
            advance((head + 1) & 0xfff, deliver);
        if (!queued)
            gapSince = 0;
        else if (!gapSince)
            gapSince = now;
    }

    template <typename Deliver>
    void bar(uint16_t ssn, uint64_t now, Deliver deliver) {
        advance(ssn, deliver);
        contiguous(now, deliver);
    }

    template <typename Deliver, typename Discard>
    void receive(Packet packet, uint16_t sn, uint64_t now, Deliver deliver, Discard discard) {
        const auto delta = distance(sn, head);
        if (!window || delta >= 2048) {
            discard(packet);
            return;
        }
        if (delta >= window)
            advance((sn - window + 1) & 0xfff, deliver);
        auto &entry = frames[sn % baWindow];
        if (entry) {
            discard(packet);
            return;
        }
        entry = packet;
        ++queued;
        contiguous(now, deliver);
    }

    template <typename Deliver>
    void finish(Deliver deliver) {
        while (queued)
            advance((head + 1) & 0xfff, deliver);
        gapSince = 0;
    }

    template <typename Deliver>
    void expire(uint64_t now, Deliver deliver) {
        if (gapSince && now >= gapSince && now - gapSince >= gapTimeoutUS)
            finish(deliver);
    }

    template <typename Discard>
    void clear(Discard discard) {
        for (auto packet : frames)
            if (packet)
                discard(packet);
        *this = {};
    }
};

struct BaResponse {
    uint8_t token;
    uint16_t status;
    uint16_t parameters;

    uint16_t window() const {
        return (parameters & baWindowMask) >> 6;
    }

    bool compatible() const {
        return (parameters & (baTidMask | baImmediate)) == baImmediate && window() != 0;
    }
};

inline bool parseBaResponse(const uint8_t *frame, size_t length, BaResponse &response) {
    if (length < 33 || frame[24] != baCategory || frame[25] != baResponse)
        return false;
    response = {frame[26], ItlAWDL::read16(frame + 27), ItlAWDL::read16(frame + 29)};
    return true;
}

inline bool parseRecipientDelba(const uint8_t *frame, size_t length, uint16_t &reason) {
    if (length < baDelbaLength || frame[24] != baCategory || frame[25] != baDelba ||
        (ItlAWDL::read16(frame + 26) & (0xf000 | delbaInitiator)))
        return false;
    reason = ItlAWDL::read16(frame + 28);
    return true;
}

}  // namespace MtkAwdl
