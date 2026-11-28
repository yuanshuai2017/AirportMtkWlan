"""Verify AWDL election, timing, channel sequences and native service preservation."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
test = r"""
#include <cassert>
#include <cstring>
#include <initializer_list>
#include <HAL/MtkAwdlAnnouncement.hpp>
#include <HAL/MtkAwdlActionFrame.hpp>
#include <HAL/MtkAwdlPeerIdentity.hpp>


const uint8_t *findTLV(const uint8_t *frame, size_t length, uint8_t type, size_t expected)
{
    for (size_t offset = 40; offset + 3 <= length;) {
        const size_t size = ItlAWDL::read16(frame + offset + 1);
        assert(size <= length - offset - 3);
        if (frame[offset] == type) {
            assert(size == expected);
            return frame + offset + 3;
        }
        offset += 3 + size;
    }
    return nullptr;
}

void testElection(const uint8_t *self)
{
    using namespace MtkAwdl;
    const uint8_t root[] = {0x10, 1, 2, 3, 4, 5};
    const uint8_t phone[] = {0x30, 1, 2, 3, 4, 5};
    uint8_t peerFrame[126] = {};
    memcpy(peerFrame + 10, phone, 6);
    uint8_t *v1 = peerFrame + 40;
    const uint8_t legacy[] = {5, 19, 0, 0, 0x34, 0x12, 2, 0,
        0x10, 1, 2, 3, 4, 5, 8, 2, 0, 0, 8, 2, 0, 0};
    memcpy(v1, legacy, sizeof(legacy));
    uint8_t *v2 = v1 + sizeof(legacy);
    const uint8_t current[] = {24, 40, 0, 0x10, 1, 2, 3, 4, 5, 0x20, 1, 2, 3, 4, 5,
        4, 3, 2, 1, 2, 0, 0, 0, 8, 2, 0, 0, 0x19, 2, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0x6e, 0, 0, 0};
    memcpy(v2, current, sizeof(current));
    uint8_t *tree = v2 + sizeof(current);
    const uint8_t path[] = {20, 18, 0, 0x10, 1, 2, 3, 4, 5, 0x20, 1, 2, 3, 4, 5,
        0x30, 1, 2, 3, 4, 5};
    memcpy(tree, path, sizeof(path));
    constexpr uint64_t anchor = 1000000;
    PeerElection legacyPeer, peer;
    assert(parsePeerElection(peerFrame, 40 + sizeof(legacy), anchor, legacyPeer));
    assert(!legacyPeer.hasCounter && legacyPeer.counter == 1 && legacyPeer.hops == 2 &&
           legacyPeer.metric == 520 && !memcmp(legacyPeer.master, root, 6));
    assert(parsePeerElection(peerFrame, sizeof(peerFrame), anchor, peer));
    assert(peer.hasCounter && peer.counter == 0x01020304 && peer.hops == 2 &&
           peer.metric == 520 && peer.treeSize == 3 && !memcmp(peer.peer, phone, 6));
    assert(!parsePeerElection(peerFrame, sizeof(peerFrame) - 1, anchor, peer));

    ItlAWDL::PeerSyncInfo sync{};
    sync.awPeriodTU = sync.awCommonTU = sync.awExtTU = 16;
    sync.awCounter = 40;
    sync.downCounterTU = 64;
    sync.masterChannel = 149;
    memcpy(sync.master, root, 6);
    sync.channels[2] = sync.channels[10] = 149;
    ItlAWDL::PeerSchedule clock{};
    clock.note(sync, anchor, 157);
    AnnouncementTiming timing{nullptr, &clock, &sync, anchor};
    AdvertisedElection info;
    ServiceSummary services;
    uint8_t output[512], tlvs[256];
    size_t length;
    const auto build = [&](uint64_t now, bool mi) {
        assert(buildAnnouncement(self, 157, 42, now, v1, sizeof(peerFrame) - 40,
            tlvs, sizeof(tlvs), output, sizeof(output), &length, &services, mi, timing, &info));
        assert(!findTLV(output, length, 5, 19));
    };
    const auto expectElection = [&](const uint8_t *master, const uint8_t *parent, uint8_t hops,
                                    uint16_t metric, const uint8_t (&rlfc)[4]) {
        uint8_t expected[40] = {};
        memcpy(expected, master, 6);
        memcpy(expected + 6, parent, 6);
        memcpy(expected + 12, rlfc, 4);
        expected[16] = hops;
        expected[20] = uint8_t(metric);
        expected[21] = uint8_t(metric >> 8);
        expected[24] = 60;
        expected[36] = 1;
        const auto *value = findTLV(output, length, 24, sizeof(expected));
        assert(value && !memcmp(value, expected, sizeof(expected)));
    };
    const auto checkSync = [&](const uint8_t *master, uint16_t aw, uint8_t down, uint8_t remain) {
        const uint8_t *params = findTLV(output, length, 4, 73);
        assert(params && !memcmp(params + 21, master, 6));
        assert(ItlAWDL::read16(params + 1) == down && ItlAWDL::read16(params + 15) == remain);
        assert(ItlAWDL::read16(params + 29) == aw);
        const uint8_t *channels = findTLV(output, length, 18, 41);
        assert(channels && params[0] == 157);
        for (unsigned slot = 0; slot < 16; ++slot) {
            assert(params[39 + slot * 2] == 0x1b && params[40 + slot * 2] == 157);
            assert(channels[6 + slot * 2] == 157);
            assert(channels[7 + slot * 2] == 124);
        }
    };
    const uint8_t standalone[] = {1, 0, 0, 0};
    const uint8_t followed[] = {4, 3, 2, 1};
    build(anchor, false);
    expectElection(self, self, 0, 60, standalone);
    assert(!info.following);
    assert(!memcmp(findTLV(output, length, 20, 6), self, 6));
    checkSync(self, 0, 64, 16);

    timing.peer = &peer;
    build(anchor + 3072, true);
    expectElection(root, phone, 3, 520, followed);
    const uint8_t *resultTree = findTLV(output, length, 20, 24);
    assert(resultTree && !memcmp(resultTree, path + 3, 18) && !memcmp(resultTree + 18, self, 6));
    assert(info.following && info.counter == 0x01020304 && info.hops == 3);
    checkSync(root, 40, 61, 13);
    assert(findTLV(output, length, 4, 73)[3] == 149);

    // Native re-elections change both counters while the forwarded root stays stable.
    v2[3 + 12] = 110;
    v2[3 + 36] = 110;
    build(anchor + 64 * 1024, false);
    expectElection(root, phone, 3, 520, followed);
    checkSync(root, 44, 64, 16);

    timing.clock = nullptr;
    build(anchor + 64 * 1024, true);
    expectElection(root, phone, 3, 520, followed);
    checkSync(root, 4, 64, 16);
    timing.clock = &clock;
    build(anchor + ItlAWDL::kPeerScheduleStaleUS, true);
    expectElection(self, self, 0, 60, standalone);
    assert(!info.following && info.counter == 1 && info.hops == 0);
    assert(!memcmp(findTLV(output, length, 20, 6), self, 6));

    v2[3 + 12] = 111;
    v2[3 + 36] = 111;
    build(anchor + 3000000, false);
    expectElection(self, self, 0, 60, standalone);

    // A missing tree falls back to root, peer and self.
    timing.peer = &legacyPeer;
    build(anchor + 3072, false);
    expectElection(root, phone, 3, 520, standalone);
    resultTree = findTLV(output, length, 20, 18);
    assert(resultTree && !memcmp(resultTree, root, 6) &&
           !memcmp(resultTree + 6, phone, 6) && !memcmp(resultTree + 12, self, 6));

    memcpy(peer.tree[1], self, 6);
    timing.peer = &peer;
    build(anchor + 3072, false);
    expectElection(self, self, 0, 60, standalone);

    sync.channels[2] = sync.channels[10] = 44;
    build(anchor + 3072, false);
    checkSync(self, 0, 61, 13);
}

int main()
{
    const uint8_t ourAddress[] = {2, 3, 4, 5, 6, 7};
    testElection(ourAddress);
    const uint8_t supplied[] = {
        18, 2, 0, 149, 124,   // Replace Tahoe's multi-channel schedule.
        4, 1, 0, 149,        // Replace Tahoe's sync data.
        6, 5, 0, 0, 0, 0, 1, 0,
        2, 3, 0, 0x12, 0x34, 0x56,
    };
    uint8_t tlvs[256], frame[512];
    size_t length = 0;
    MtkAwdl::ServiceSummary services;
    assert(MtkAwdl::buildAnnouncement(ourAddress, 36, 1, 500000, supplied,
        sizeof(supplied), tlvs, sizeof(tlvs), frame, sizeof(frame), &length, &services, true));
    assert(MtkAwdl::actionFrameLength(frame, length) == length);
    assert(services.records == 1 && frame[30] == 3 && frame[22] == 0x10);
    assert(!memcmp(frame + 10, ourAddress, 6));
    assert(frame[43] == 36 && frame[46] == 36);
    const size_t slots = 43 + 73;
    assert(frame[slots] == 18);
    for (size_t index = 0; index < 16; ++index) {
        assert(frame[slots + 9 + index * 2] == 36);
        assert(frame[slots + 10 + index * 2] == 115);
    }
    assert(!memcmp(frame + slots + 44, supplied + 9, sizeof(supplied) - 9));
    assert(length == slots + 44 + sizeof(supplied) - 9 + 43 + 9);
    for (const uint8_t channel : {uint8_t(6), uint8_t(44), uint8_t(149), uint8_t(165)}) {
        assert(MtkAwdl::buildAnnouncement(ourAddress, channel, 1, 500000, supplied,
            sizeof(supplied), tlvs, sizeof(tlvs), frame, sizeof(frame), &length, &services, true));
        assert(MtkAwdl::actionFrameLength(frame, length) == length);
        assert(frame[43] == channel && frame[46] == channel);
        for (size_t index = 0; index < 16; ++index) {
            assert(frame[slots + 9 + index * 2] == channel);
            assert(frame[slots + 10 + index * 2] == ItlAWDL::globalOperatingClass20(channel));
            assert(frame[43 + 39 + index * 2] == ItlAWDL::legacySlotFlags(channel));
            assert(frame[43 + 40 + index * 2] == channel);
        }
    }
    assert(!MtkAwdl::buildAnnouncement(ourAddress, 52, 1, 500000, supplied,
        sizeof(supplied), tlvs, sizeof(tlvs), frame, sizeof(frame), &length, &services, true));
    assert(MtkAwdl::buildAnnouncement(ourAddress, 36, 2, 612640, supplied, 17,
        tlvs, sizeof(tlvs), frame, sizeof(frame), &length, &services, false));
    assert(frame[30] == 0 && !services.advertisesService());
    const uint8_t ptr[] = {3, 0, 0xc0, 7, 12, 4, 0, 0, 0, 1, 'x', 0xc0, 7};
    assert(MtkAwdl::isAirDropPtr(ptr, sizeof(ptr)));
    using MtkAwdl::PtrResult;
    assert(MtkAwdl::inspectAirDropPtr(ptr, sizeof(ptr) - 1) == PtrResult::BadLength);
    assert(MtkAwdl::inspectAirDropPtr(ptr, 6) == PtrResult::BadLength);
    const uint8_t wrongType[] = {3, 0, 0xc0, 7, 16};
    assert(MtkAwdl::inspectAirDropPtr(wrongType, sizeof(wrongType)) == PtrResult::WrongType);
    const uint8_t unknown[] = {100, 0, 0xc0, 7, 12};
    assert(MtkAwdl::inspectAirDropPtr(unknown, sizeof(unknown)) == PtrResult::UnknownLayout);
    assert(MtkAwdl::hasAirDropNameHint(unknown, sizeof(unknown)));
    const uint8_t badTarget[] = {3, 0, 0xc0, 7, 12, 4, 0, 0, 0, 1, 'x', 0xc0, 1};
    assert(MtkAwdl::inspectAirDropPtr(badTarget, sizeof(badTarget)) == PtrResult::BadTarget);
    MtkAwdl::ServiceSummary diag;
    diag.add(2, wrongType, sizeof(wrongType));
    diag.add(2, unknown, sizeof(unknown));
    diag.add(2, badTarget, sizeof(badTarget));
    assert(!diag.airDropPtrs && diag.airDropOtherTypes == 1 && diag.airDropBadTargets == 1 &&
           diag.serviceUnknownLayouts == 1 && diag.airDropOtherHints == 1);
    const uint8_t foreign[] = {3, 0, 0xc0, 1, 12, 4, 0, 0, 0, 1, 'x', 0xc0, 7};
    assert(!MtkAwdl::isAirDropPtr(foreign, sizeof(foreign)));
    const uint8_t abbreviated[] = {
        2, 11, 0, 3, 0, 0xc0, 7, 12, 2, 0, 0, 0, 1, 'x',
        2, 19, 0, 5, 0, 1, 'X', 0xc0, 7, 33, 8, 0, 0, 0,
        0, 0, 0, 0, 0x34, 0x56, 0xc0, 12
    };
    assert(MtkAwdl::buildAnnouncement(ourAddress, 36, 3, 500000, abbreviated, sizeof(abbreviated),
        tlvs, sizeof(tlvs), frame, sizeof(frame), &length, &diag, true));
    assert(diag.airDropPtrs == 1 && diag.airDropCorroborated == 1 && !diag.airDropBadTargets);
    assert(!memcmp(frame + slots + 44, abbreviated, sizeof(abbreviated)));
    assert(MtkAwdl::buildAnnouncement(ourAddress, 36, 3, 500000, abbreviated, 14,
        tlvs, sizeof(tlvs), frame, sizeof(frame), &length, &diag, true));
    assert(!diag.airDropPtrs && diag.airDropBadTargets == 1 && diag.airDropShortTargets == 1);
    assert(diag.airDropTargetBytes == 2 && diag.airDropTargetLabelBytes == 1);

    uint8_t identity[50] = {};
    const uint8_t arpa[] = {16, 7, 0, 0, 5, 'P', 'h', 'o', 'n', 'e'};
    memcpy(identity + 40, arpa, sizeof(arpa));
    assert(MtkAwdl::matchHostname(identity, sizeof(identity), "phone"));
    assert(!MtkAwdl::matchHostname(identity, sizeof(identity), "phone2"));
    assert(!MtkAwdl::matchHostname(identity, sizeof(identity), "phon"));
    assert(!MtkAwdl::matchHostname(identity, sizeof(identity) - 1, "phone"));
    assert(MtkAwdl::inspectArpaName(identity, sizeof(identity), "phone") == MtkAwdl::ArpaName::DnsLabel);
    const uint8_t nativeArpa[] = {16, 7, 0, 0, 'P', 'h', 'o', 'n', 'e', 0};
    memcpy(identity + 40, nativeArpa, sizeof(nativeArpa));
    assert(MtkAwdl::inspectArpaName(identity, sizeof(identity), "phone") == MtkAwdl::ArpaName::PlainLabel);
    assert(MtkAwdl::inspectArpaName(identity, sizeof(identity), "phon") == MtkAwdl::ArpaName::Other);
    assert(MtkAwdl::matchNativeHostname("PhOnE.LoCaL", "phone"));
    assert(!MtkAwdl::matchNativeHostname("phone2", "phone"));
    assert(!MtkAwdl::matchNativeHostname("abcdefghijklmnopqrstuvwxyzabcdef", "phone"));
    const uint8_t compressed[] = {0xc0, 9, 0xc0, 10};
    assert(MtkAwdl::localAirDropName(compressed, sizeof(compressed), false));
    uint8_t mi[] = {24, 28, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        35, 2, 0, 1, 1,
        2, 13, 0, 3, 0, 0xc0, 7, 12, 4, 0, 0, 0, 1, 'x', 0xc0, 7,
    };
    assert(MtkAwdl::inspectMasterIndication(mi, sizeof(mi), services));
    assert(services.records == 1 && services.airDrop && services.airDropPtrs == 1);
    assert(MtkAwdl::buildAnnouncement(ourAddress, 36, 3, 500000, mi, sizeof(mi),
        tlvs, sizeof(tlvs), frame, sizeof(frame), &length, &services, true));
    assert(frame[30] == 3 && services.records == 1 && services.airDrop);
    assert(!memcmp(frame + slots + 44, mi + 31, sizeof(mi) - 31));
    assert(!MtkAwdl::inspectMasterIndication(mi, sizeof(mi) - 1, services));
    assert(!MtkAwdl::inspectMasterIndication(mi + 31, sizeof(mi) - 31, services));
    mi[35] = 0;
    assert(MtkAwdl::inspectMasterIndication(mi, sizeof(mi) - 16, services));
    assert(!services.advertisesService());
    assert(!MtkAwdl::buildAnnouncement(ourAddress, 36, 1, 0, supplied, sizeof(supplied)-1,
        tlvs, sizeof(tlvs), frame, sizeof(frame), &length, &services, true));
    assert(!MtkAwdl::buildAnnouncement(ourAddress, 36, 1, 0, supplied, sizeof(supplied),
        tlvs, sizeof(tlvs), frame, 80, &length, &services, true));
}
"""
with tempfile.TemporaryDirectory(prefix="mtk-awdl-announcement-") as directory:
    source = Path(directory) / "test.cpp"
    binary = Path(directory) / "test"
    source.write_text(test)
    subprocess.run(["clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", "-I", str(root / "include"),
                    str(source), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
