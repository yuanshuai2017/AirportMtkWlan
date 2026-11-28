"""Check AWDL RX validation and native-only Action keepalives."""
from pathlib import Path
import subprocess
import tempfile
import zlib

root = Path(__file__).resolve().parents[2]
action = bytearray(40)
action[0] = 0xd0
action[16:22] = bytes.fromhex("002500ff9473")
action[24:31] = bytes.fromhex("7f0017f2081003")
action.extend(bytes([4, 27, 0]) + bytes(27))
fcs = zlib.crc32(action).to_bytes(4, "little")
fixture = ",".join(str(value) for value in action + fcs)
interface = (root / "AirportMtkWlan/MtkAwdlInterface.cpp").read_text()
keepalive_service = interface[
    interface.index("void MtkAWDLInterface::serviceNativeKeepalives("):
    interface.index("void MtkAWDLInterface::observeAction(")
]
test = r"""
#include <cassert>
#include <vector>
#include <HAL/MtkAwdlAnnouncement.hpp>

struct AirportItlwm {};
struct apple80211_awdl_sync_enabled { bool enabled; };
void IOLockLock(int *) {}
void IOLockUnlock(int *) {}
constexpr int kIOReturnSuccess = 0;

struct MtkAWDLInterface {
    uint32_t activeChannel = 157;
    bool nativeStarted = true;
    int lock = 0, *configurationLock = &lock;
    struct {
        bool enabled = true;
        void readSyncEnabled(apple80211_awdl_sync_enabled *sync) { sync->enabled = enabled; }
    } configuration;
    struct Observation {
        uint8_t address[6] = {2, 3, 4, 5, 6, 7};
        uint32_t channel = 157;
        uint64_t lastFrameUS = 1000000, lastActionRxUS = lastFrameUS;
        uint64_t lastKeepaliveUS = 0, lastDataRxUS = 0;
        uint16_t keepaliveSeq = 4095;
        size_t lastActionLength = 0;
        int32_t lastActionRssi = -39;
        uint8_t lastAction[MtkAwdl::nativeKeepaliveActionMax] = {};
    } observedPeers[1];
    uint32_t nativeKeepalives = 0;
    unsigned submitted = 0;
    bool accepts = true;
    uint8_t lastSubmission[MtkAwdl::nativeKeepaliveActionMax] = {};
    void setProperty(const char *key, uint32_t value, unsigned bits) {
        assert(!strcmp(key, "MtkAwdlNativeKeepalives") && value == nativeKeepalives && bits == 32);
    }
    int submitNativeAction(AirportItlwm *, const uint8_t *frame, size_t length, uint32_t channel, int32_t rssi) {
        assert(channel == 157 && rssi == -39);
        ++submitted;
        memcpy(lastSubmission, frame, length);
        return accepts ? kIOReturnSuccess : 1;
    }
    void serviceNativeKeepalives(AirportItlwm *, uint64_t, const MtkAwdl::UnicastAcks &);
};
""" + keepalive_service + r"""

void testNativeKeepalives()
{
    using namespace ItlAWDL;
    using namespace MtkAwdl;
    MtkAWDLInterface iface;
    auto &entry = iface.observedPeers[0];
    assert(buildTransportProbe(entry.address, 0, entry.lastAction, sizeof(entry.lastAction),
                              &entry.lastActionLength) == BuildResult::Ready);
    uint8_t body[] = {4, 31, 0, 157, 53, 0, 157, 0, 16, 0, 110, 0, 0, 0, 16, 0, 16, 0, 5, 0,
                     3, 3, 3, 3, 2, 3, 4, 5, 6, 7, 4, 0, 252, 255};
    memcpy(entry.lastAction + entry.lastActionLength, body, sizeof(body));
    entry.lastActionLength += sizeof(body);
    write16(entry.lastAction + 22, 0xfff0);
    write32(entry.lastAction + 32, 0xfffffff0);
    write32(entry.lastAction + 36, 0x12345678);
    uint8_t original[sizeof(entry.lastAction)];
    memcpy(original, entry.lastAction, sizeof(original));

    UnicastAcks acks;
    const uint64_t first = entry.lastFrameUS + nativeKeepaliveIntervalUS;
    const uint8_t other[] = {4, 5, 6, 7, 8, 9};
    acks.note(other, first - 1);
    iface.serviceNativeKeepalives(nullptr, first, acks);
    assert(!iface.submitted);
    acks.note(entry.address, first - 2);
    iface.serviceNativeKeepalives(nullptr, first - 1, acks);
    assert(!iface.submitted);
    iface.configuration.enabled = false;
    iface.serviceNativeKeepalives(nullptr, first, acks);
    assert(!iface.submitted);
    iface.configuration.enabled = true;
    iface.activeChannel = 149;
    iface.serviceNativeKeepalives(nullptr, first, acks);
    assert(!iface.submitted);
    iface.activeChannel = 157;
    iface.accepts = false;
    iface.serviceNativeKeepalives(nullptr, first, acks);
    assert(!iface.nativeKeepalives && !entry.lastKeepaliveUS && entry.keepaliveSeq == 4095);
    iface.accepts = true;
    iface.serviceNativeKeepalives(nullptr, first, acks);
    assert(iface.nativeKeepalives == 1 && entry.lastKeepaliveUS == first);
    auto *action = iface.lastSubmission;
    assert(read16(action + 22) == 0 && entry.keepaliveSeq == 0);
    assert(read32(action + 32) == 1999984 && read32(action + 36) == 0x12345678 + 2000000);
    // From AW 65532/phase 11, advance 1953 TU: new phase 44, after AW counter wrap.
    assert(read16(action + 43 + 29) == 118 && read16(action + 43 + 1) == 20);
    assert(read16(action + 43 + 15) == 0);
    assert(!memcmp(original, entry.lastAction, sizeof(original)));
    assert(entry.lastFrameUS == 1000000 && entry.lastActionRxUS == 1000000);

    const uint64_t second = first + nativeKeepaliveIntervalUS;
    entry.lastDataRxUS = second - 1;
    iface.serviceNativeKeepalives(nullptr, second - 1, acks);
    assert(iface.nativeKeepalives == 1);
    iface.serviceNativeKeepalives(nullptr, second, acks);
    assert(iface.nativeKeepalives == 2 && entry.keepaliveSeq == 1);
    assert(read32(action + 32) == 3999984 && entry.lastFrameUS == 1000000);
    iface.serviceNativeKeepalives(nullptr, second + nativeKeepaliveIntervalUS - 1, acks);
    assert(iface.nativeKeepalives == 2); // RX at exactly the expiry boundary cannot sustain the peer.
    assert(!nativeKeepaliveDue(first, first - 1, 0, first - 1, 0)); // Real Actions reset the delay.

    uint8_t result[nativeKeepaliveActionMax];
    assert(refreshNativeAction(original, entry.lastActionLength, 54 * 1024ULL + 17, 3,
                               result, sizeof(result)));
    assert(read16(result + 22) == 64 && read16(result + 43 + 29) == 0);
    assert(read16(result + 43 + 1) == 63 && read16(result + 43 + 15) == 15);
    assert(!refreshNativeAction(original, entry.lastActionLength - 1, 0, 0, result, sizeof(result)));
    assert(!refreshNativeAction(original, entry.lastActionLength, 0, 0, result, 32));
    original[43 + 27] = 0;
    assert(!refreshNativeAction(original, entry.lastActionLength, 0, 0, result, sizeof(result)));
}

int main()
{
    testNativeKeepalives();
    const uint8_t capture[] = {""" + fixture + r"""};
    const size_t length = sizeof(capture) - 4;
    assert(MtkAwdl::actionFrameLength(capture, sizeof(capture)) == length);
    assert(MtkAwdl::actionFrameLength(capture, length) == length);
    assert(!MtkAwdl::actionFrameLength(nullptr, length));
    assert(!MtkAwdl::actionFrameLength(capture, length - 1));
    assert(!MtkAwdl::actionFrameLength(capture, 40));

    std::vector<uint8_t> data(capture, capture + length);
    for (size_t field : {size_t(0), size_t(16), size_t(24), size_t(29)}) {
        data[field] ^= 1;
        assert(!MtkAwdl::actionFrameLength(data.data(), data.size()));
        data[field] ^= 1;
    }
    data[1] = 0x40;
    assert(!MtkAwdl::actionFrameLength(data.data(), data.size()));
    data[1] = 0;
    data[22] = 1;
    assert(!MtkAwdl::actionFrameLength(data.data(), data.size()));
    data[22] = 0;
    data[30] = 0;
    assert(MtkAwdl::actionFrameLength(data.data(), data.size()) == length);
    data[41] = 30;
    assert(!MtkAwdl::actionFrameLength(data.data(), data.size()));
    data[41] = 27;
    data.insert(data.end(), capture + 40, capture + length);
    assert(!MtkAwdl::actionFrameLength(data.data(), data.size()));
    data.resize(length);
    data[40] = 3;
    assert(!MtkAwdl::actionFrameLength(data.data(), data.size()));
    data[40] = 4;
    data.resize(MtkAwdl::maximumFrameLength + 1);
    assert(!MtkAwdl::actionFrameLength(data.data(), data.size()));

    data.assign(capture, capture + sizeof(capture));
    data.back() ^= 0x80;
    assert(!MtkAwdl::actionFrameLength(data.data(), data.size()));
}
"""
with tempfile.TemporaryDirectory(prefix="mtk-awdl-action-") as temporary:
    folder = Path(temporary)
    source = folder / "test.cpp"
    binary = folder / "test"
    source.write_text(test)
    subprocess.run(["clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", "-I", str(root / "include"),
                    str(source), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
