"""Validate the driver's AWDL station transaction ordering and MCU wire bytes."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
body = r"""
#include <cassert>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>
#include <algorithm>

#define __packed __attribute__((packed))
#define __aligned(x) __attribute__((aligned(x)))
#define IEEE80211_ADDR_LEN 6
#define IEEE80211_NWID_LEN 32
#undef htole16
#undef htole32
#define htole16(x) (uint16_t(x))
#define htole32(x) (uint32_t(x))
#define GENMASK(high, low) ((UINT32_MAX >> (31 - (high))) & (UINT32_MAX << (low)))
#include "if_mwxreg.h"
#include "MtkMwxAwdlPeer.hpp"
#include <HAL/MtkAwdlAnnouncement.hpp>

using namespace MwxAwdlPeer;

static const uint8_t firstMac[] = {2, 1, 2, 3, 4, 5};
static const uint8_t nextMac[] = {6, 5, 4, 3, 2, 1};

static void testBaActionAndState()
{
    using namespace MtkAwdl;
    TxBa ba = {};
    ba.nextSequence = 4095;
    uint8_t request[baRequestLength];
    buildBaRequest(request, firstMac, nextMac, 9, ba.nextSequence);
    const uint8_t expected[] = {
        0xd0, 0, 0, 0, 6, 5, 4, 3, 2, 1, 2, 1, 2, 3, 4, 5,
        0, 0x25, 0, 0xff, 0x94, 0x73, 0, 0, 3, 0, 9, 2, 16, 0, 0, 0xf0, 0xff
    };
    assert(sizeof(request) == sizeof(expected) && !memcmp(request, expected, sizeof(expected)));
    assert(isPeerBaAction(request, sizeof(request), nextMac, firstMac));
    assert(!isPeerBaAction(request, sizeof(request), firstMac, nextMac));
    assert(!isPeerBaAction(request, 25, nextMac, firstMac));
    request[1] = 0x40;
    assert(!isPeerBaAction(request, sizeof(request), nextMac, firstMac));

    assert(!baRequestWindow(false, 30000, 29999));
    assert(!baRequestWindow(true, 30000, 0));
    assert(!baRequestWindow(true, 30000, 30001));
    assert(!baRequestWindow(true, 30000, 9999));
    assert(baRequestWindow(true, 30000, 10000));
    ba.request(9, 1000);
    assert(!ba.holdData() && ba.requested());
    assert(ba.ssn == 4095 && !ba.active() && !ba.expired(400999) && ba.expired(401000));
    uint8_t response[baRequestLength];
    buildBaHeader(response, sizeof(response), nextMac, firstMac, baResponse);
    assert(isPeerBaAction(response, sizeof(response), firstMac, nextMac));
    memcpy(response + 16, nextMac, 6);
    assert(isPeerBaAction(response, sizeof(response), firstMac, nextMac));
    memcpy(response + 16, firstMac, 6);
    assert(!isPeerBaAction(response, sizeof(response), firstMac, nextMac));
    response[26] = 8;
    ItlAWDL::write16(response + 29, (32 << 6) | baImmediate);
    BaResponse result;
    assert(!parseBaResponse(response, 32, result));
    assert(parseBaResponse(response, sizeof(response), result) && result.window() == 32);
    assert(!ba.accept(result, 2000));
    response[26] = 9;
    ItlAWDL::write16(response + 27, 37);
    assert(parseBaResponse(response, sizeof(response), result) && !ba.accept(result, 2000));
    ItlAWDL::write16(response + 27, 0);
    ItlAWDL::write16(response + 29, (80 << 6) | baImmediate | (1 << 2));
    assert(parseBaResponse(response, sizeof(response), result) && !ba.accept(result, 2000));
    ItlAWDL::write16(response + 29, (80 << 6) | baImmediate);
    assert(parseBaResponse(response, sizeof(response), result) && ba.accept(result, 2000));
    assert(!ba.accept(result, 2000) && ba.window == 64 && ba.nextSequence == ba.ssn);
    assert(!ba.activate(0) && (dataBaFlags(0, true, ba, true, MT_PHY_TYPE_VHT) & MT_TXD3_BA_DISABLE));
    assert(ba.holdData() && !ba.expired(11999) && ba.expired(12000));
    ba.firmwareMayExist = true;
    assert(!ba.holdData() && !ba.expired(12000));
    assert(!ba.activate(EIO) && !ba.active());
    assert(ba.activate(0) && ba.active());
    assert(!(dataBaFlags(MT_TXD3_BA_DISABLE, true, ba, true, MT_PHY_TYPE_VHT) & MT_TXD3_BA_DISABLE));
    assert(!(dataBaFlags(MT_TXD3_BA_DISABLE, true, ba, true, MT_PHY_TYPE_OFDM) & MT_TXD3_BA_DISABLE));
    assert(dataBaFlags(0, false, ba, true, MT_PHY_TYPE_VHT) & MT_TXD3_BA_DISABLE);
    assert(dataBaFlags(0, true, ba, false, MT_PHY_TYPE_VHT) & MT_TXD3_BA_DISABLE);
    assert(dataBaFlags(0, true, ba, true, MT_PHY_TYPE_OFDM, true) & MT_TXD3_BA_DISABLE);
    assert(!(dataBaFlags(MT_TXD3_BA_DISABLE, true, ba, true, MT_PHY_TYPE_VHT, true) & MT_TXD3_BA_DISABLE));
    ba.submitted();
    assert(ba.nextSequence == 0);

    uint8_t delba[baDelbaLength];
    buildDelba(delba, nextMac, firstMac);
    uint16_t reason = 0;
    assert(!parseRecipientDelba(delba, sizeof(delba), reason));
    assert(delba[27] == 8 && delba[28] == 37);
    delba[27] = 0x10; // Another TID.
    assert(!parseRecipientDelba(delba, sizeof(delba), reason));
    delba[27] = 0;
    assert(parseRecipientDelba(delba, sizeof(delba), reason) && reason == 37);
    ba.stop(PeerBaState::Failed);
    assert(!ba.active() && ba.firmwareMayExist && !ba.activate(0));
    assert(dataBaFlags(0, true, ba, true, MT_PHY_TYPE_HT) & MT_TXD3_BA_DISABLE);
}

using std::min;
constexpr size_t ETHER_ADDR_LEN = 6;
struct Packet { const uint8_t *bytes; size_t length; };
using mbuf_t = const Packet *;
struct ieee80211_node {};
constexpr int IEEE80211_S_RUN = 4;
struct mwx_softc {
    bool sc_awdl_dev_active, sc_awdl_ba_enabled, sc_awdl_rx_ba_enabled, sc_resetting;
    struct { int ic_state; ieee80211_node *ic_bss; } sc_ic;
    struct { struct { ieee80211_node ni; } vif_mn; } sc_vif;
    uint8_t sc_awdl_mac[6], sc_awdl_tx_channel;
    Slot sc_awdl_peer;
    MtkAwdl::RxReorder<mbuf_t> sc_awdl_reorder[rxBaTids];
    MtkAwdl::AnnouncementCompletions sc_awdl_completions;
    int sc_nswq, sc_awdl_ba_task;
};
size_t mbuf_pkthdr_len(mbuf_t packet) { return packet->length; }
int mbuf_copydata(mbuf_t packet, size_t offset, size_t length, void *out) {
    assert(offset + length <= packet->length);
    memcpy(out, packet->bytes + offset, length);
    return 0;
}
void IOLog(const char *, ...) {}
static void mwx_awdl_ba_error(struct mwx_softc *, uint32_t, bool, bool = false);
void task_add(int, int *) {}
static uint64_t rxBaNowUS = 2000;
uint64_t mwx_now_us() { return rxBaNowUS; }

static std::vector<int> rxBaCommands;
static uint32_t rxBaMcuError;
static bool rxBaQuarantined;

struct MwxAwdlPeerFirmware {
    bool canInstall(uint8_t channel) const { return channel == 157; }
    uint32_t clearRxBa(RxBa &ba, const uint8_t *) const {
        rxBaCommands.push_back(2);
        ba.active = ba.firmwareMayExist = false;
        return 0;
    }
    uint32_t programRxBa(RxBa &ba, const uint8_t *, bool enable) const {
        assert(enable && ba.firmwareMayExist && !ba.active);
        rxBaCommands.push_back(1);
        return rxBaMcuError;
    }
};
static int mwx_awdl_ba_send(struct mwx_softc *, struct ieee80211_node *, const uint8_t *frame, size_t size) {
    MtkAwdl::BaResponse response;
    assert(MtkAwdl::parseBaResponse(frame, size, response));
    rxBaCommands.push_back(response.status ? 4 : 3);
    return 0;
}
static unsigned rxBaFlushes;
static void mwx_awdl_rx_deliver(struct mwx_softc *, mbuf_t, uint8_t) { ++rxBaFlushes; }
static void mwx_awdl_peer_error(struct mwx_softc *, Failure) { assert(false); }
static void mwx_awdl_peer_quarantine(struct mwx_softc *) { rxBaQuarantined = true; }

// BA_ERROR_AND_RX

static void testBaRxDiagnostics()
{
    using namespace MtkAwdl;
    mwx_softc sc = {};
    sc.sc_awdl_dev_active = sc.sc_awdl_ba_enabled = sc.sc_awdl_rx_ba_enabled = sc.sc_awdl_peer.active = true;
    sc.sc_awdl_tx_channel = sc.sc_awdl_peer.channel = 157;
    memcpy(sc.sc_awdl_mac, firstMac, 6);
    memcpy(sc.sc_awdl_peer.mac, nextMac, 6);
    auto &ba = sc.sc_awdl_peer.ba;
    const auto &counts = sc.sc_awdl_completions;
    ba.request(9, 1000);
    uint8_t frame[baRequestLength];
    buildBaHeader(frame, sizeof(frame), nextMac, firstMac, baResponse);
    const Packet packet = {frame, sizeof(frame)};
    frame[26] = 9;
    ItlAWDL::write16(frame + 29, (32 << 6) | baImmediate);
    frame[4] ^= 2;
    assert(!mwx_awdl_ba_rx(&sc, &packet, 157));
    assert(counts.peerBaRxAny == 1 && counts.peerBaRxRejected == 0);
    frame[4] ^= 2;
    assert(mwx_awdl_ba_rx(&sc, &packet, 149));
    memcpy(frame + 16, firstMac, 6);
    assert(mwx_awdl_ba_rx(&sc, &packet, 157));
    memcpy(frame + 16, nextMac, 6);
    frame[26] = 8;
    ItlAWDL::write16(frame + 27, 37);
    assert(mwx_awdl_ba_rx(&sc, &packet, 157));
    assert(counts.peerBaRxAny == 4 && counts.peerBaRxRejected == 3);
    assert(counts.peerBaRxRejectFilter == 3 && counts.peerBaRxRejectResponder == 0);
    assert(counts.peerBaRxLastStatus == 37 && !ba.accepted() && counts.peerBaErrors == 0);
    frame[26] = 9;
    ItlAWDL::write16(frame + 27, 0);
    assert(mwx_awdl_ba_rx(&sc, &packet, 157));
    assert(counts.peerBaRxAny == 5 && counts.peerBaRxRejected == 3);
    assert(counts.peerBaRxLastStatus == 0 && ba.accepted() && counts.peerBaRespOk == 1);

    buildBaRequest(frame, nextMac, firstMac, 14, 300);
    ItlAWDL::write16(frame + 27, (80 << 6) | (5 << 2) | baImmediate | 1);
    assert(mwx_awdl_ba_rx(&sc, &packet, 157));
    auto &rx5 = sc.sc_awdl_peer.rxBa[5];
    assert(counts.peerBaRxReq == 1 && counts.peerBaRxRejected == 3);
    assert(rx5.pending && !rx5.active && rx5.pendingRequest.token == 14);
    assert(rx5.pendingRequest.tid == 5 && rx5.pendingRequest.ssn == 300 && rx5.pendingRequest.window == 64);
    buildBaResponse(frame, firstMac, nextMac, rx5.pendingRequest, 0);
    BaResponse response;
    assert(parseBaResponse(frame, sizeof(frame), response) && response.status == 0);
    assert(response.token == 14 && response.parameters == ((64 << 6) | (5 << 2) | baImmediate));
    buildBaHeader(frame, sizeof(frame), nextMac, firstMac, baDelba);
    ItlAWDL::write16(frame + 26, (5 << 12) | delbaInitiator);
    assert(mwx_awdl_ba_rx(&sc, &packet, 157) && !rx5.pending && rx5.stopping);
    assert(ba.accepted());

    // Service the next request. A failed MCU command must retire its
    // partial context before the response, and a duplicate must not reset SN.
    MwxAwdlPeerFirmware firmware;
    mwx_awdl_rx_ba_service(&sc, firmware, 5);
    auto &rx = sc.sc_awdl_peer.rxBa[0];
    buildBaRequest(frame, nextMac, firstMac, 7, 300);
    assert(mwx_awdl_ba_rx(&sc, &packet, 157));
    rxBaMcuError = EIO;
    mwx_awdl_rx_ba_service(&sc, firmware, 0);
    assert((rxBaCommands == std::vector<int>{1, 2, 4}));
    assert(!rx.active && counts.peerBaRxRespSent == 0 && !rxBaQuarantined);
    assert(counts.peerBaRxRejectFilter == 3 && counts.peerBaRxRejectResponder == 1);

    rxBaMcuError = 0;
    rxBaCommands.clear();
    assert(mwx_awdl_ba_rx(&sc, &packet, 157));
    mwx_awdl_rx_ba_service(&sc, firmware, 0);
    assert((rxBaCommands == std::vector<int>{1, 3}));
    assert(rx.active && counts.peerBaRxRespSent == 1 && sc.sc_awdl_reorder[0].head == 300);
    sc.sc_awdl_reorder[0].head = 312;
    assert(mwx_awdl_ba_rx(&sc, &packet, 157));
    mwx_awdl_rx_ba_service(&sc, firmware, 0);
    assert((rxBaCommands == std::vector<int>{1, 3, 3}));
    assert(counts.peerBaRxRespSent == 2 && sc.sc_awdl_reorder[0].head == 312);
    // Requests arriving for both TIDs before the worker runs keep their own
    // pending request and cannot replace the existing TID 0 reorder window.
    assert(mwx_awdl_ba_rx(&sc, &packet, 157));
    buildBaRequest(frame, nextMac, firstMac, 20, 700);
    ItlAWDL::write16(frame + 27, (64 << 6) | (1 << 2) | baImmediate);
    assert(mwx_awdl_ba_rx(&sc, &packet, 157));
    auto &rx1 = sc.sc_awdl_peer.rxBa[1];
    assert(rx.pending && rx1.pending);
    mwx_awdl_rx_ba_service(&sc, firmware, 0);
    mwx_awdl_rx_ba_service(&sc, firmware, 1);
    assert(rx.active && rx1.active && counts.peerBaRxOtherTid == 0);
    assert(sc.sc_awdl_reorder[0].head == 312 && sc.sc_awdl_reorder[1].head == 700);
    assert(counts.peerBaRxTidMask == ((1 << 0) | (1 << 1) | (1 << 5)));

    sc.sc_awdl_reorder[1].receive(&packet, 702, 1500, [](mbuf_t) {}, [](mbuf_t) {});
    buildBaHeader(frame, sizeof(frame), nextMac, firstMac, baDelba);
    ItlAWDL::write16(frame + 26, (1 << 12) | delbaInitiator);
    assert(mwx_awdl_ba_rx(&sc, &packet, 157));
    mwx_awdl_rx_ba_service(&sc, firmware, 1);
    assert(rx.active && !rx1.active && !rx1.firmwareMayExist && rxBaFlushes == 1);

    // Deliver buffered frames before same-TID renegotiation resets WTBL.
    sc.sc_awdl_reorder[0].receive(&packet, 315, 1000, [](mbuf_t) {}, [](mbuf_t) {});
    buildBaRequest(frame, nextMac, firstMac, 8, 320);
    assert(mwx_awdl_ba_rx(&sc, &packet, 157));
    mwx_awdl_rx_ba_service(&sc, firmware, 0);
    assert(counts.peerBaRxReconfigs == 1 && rxBaFlushes == 2 && sc.sc_awdl_reorder[0].head == 320);

    // Same SSN after the reorder window has advanced >= baWindow must reset WTBL and head
    // (e.g. peer uncached Mac after a transfer and re-cached with SSN reset to 0).
    sc.sc_awdl_reorder[0].head = (320 + 496) & 0xfff;
    rxBaCommands.clear();
    buildBaRequest(frame, nextMac, firstMac, 8, 320);
    assert(mwx_awdl_ba_rx(&sc, &packet, 157));
    mwx_awdl_rx_ba_service(&sc, firmware, 0);
    assert((rxBaCommands == std::vector<int>{2, 1, 3}));
    assert(counts.peerBaRxReconfigs == 2 && sc.sc_awdl_reorder[0].head == 320);

    // Same SSN with a new dialog token must also reconfigure.
    sc.sc_awdl_reorder[0].head = 325;
    rxBaCommands.clear();
    buildBaRequest(frame, nextMac, firstMac, 9, 320);
    assert(mwx_awdl_ba_rx(&sc, &packet, 157));
    mwx_awdl_rx_ba_service(&sc, firmware, 0);
    assert((rxBaCommands == std::vector<int>{2, 1, 3}));
    assert(counts.peerBaRxReconfigs == 3 && sc.sc_awdl_reorder[0].head == 320);

    // Same SSN and same token after duplicateWindowUS (idle uncache/re-cache) must reconfigure.
    sc.sc_awdl_reorder[0].head = 325;
    rxBaNowUS += RxBa::duplicateWindowUS;
    rxBaCommands.clear();
    buildBaRequest(frame, nextMac, firstMac, 9, 320);
    assert(mwx_awdl_ba_rx(&sc, &packet, 157));
    mwx_awdl_rx_ba_service(&sc, firmware, 0);
    assert((rxBaCommands == std::vector<int>{2, 1, 3}));
    assert(counts.peerBaRxReconfigs == 4 && sc.sc_awdl_reorder[0].head == 320);
    rxBaNowUS = 2000;

    sc.sc_awdl_rx_ba_enabled = false;
    assert(mwx_awdl_ba_rx(&sc, &packet, 157));
    mwx_awdl_rx_ba_service(&sc, firmware, 0);
    assert(rxBaCommands.back() == 4 && counts.peerBaRxRespSent == 8);
}

static void testBaRetryBudget()
{
    using MtkAwdl::PeerBaState;
    TxBa ba = {};
    uint64_t now = 30000;
    for (uint8_t i = 0; i < 4; ++i) {
        assert(ba.canRequest(now));
        ba.request(i + 1, now);
        assert(ba.attempts == i + 1 && !ba.canRequest(now + TxBa::retryUS));
        now += TxBa::timeoutUS;
        assert(ba.expired(now));
        ba.stop(PeerBaState::Failed, true);
        assert(!ba.canRequest(now) && !ba.holdData());
        ba.retryAllowed = true;
        ba.nextRequestUS = now + TxBa::retryUS;
        assert(!ba.canRequest(ba.nextRequestUS - 1));
        now = ba.nextRequestUS;
    }
    assert(!ba.canRequest(now) && !ba.canRequest(now + TxBa::retryUS));

    // Recipient DELBA after an active BA session must return to Idle with cooldown
    // and reset attempt budget so subsequent transfers re-enable hardware A-MPDU.
    TxBa recovered = {};
    recovered.nextSequence = 10;
    recovered.request(1, 50000);
    MtkAwdl::BaResponse okResp = {1, 0, uint16_t((64 << 6) | MtkAwdl::baImmediate)};
    assert(recovered.accept(okResp, 50100));
    recovered.firmwareMayExist = true;
    assert(recovered.activate(0) && recovered.active() && recovered.hardwareSequence);
    recovered.onRecipientDelba(60000);
    assert(recovered.state == PeerBaState::Idle && recovered.attempts == 0);
    assert(!recovered.canRequest(60000 + TxBa::retryUS));  // firmwareMayExist still true
    recovered.firmwareMayExist = false;
    assert(!recovered.canRequest(60000 + TxBa::retryUS - 1));
    assert(recovered.canRequest(60000 + TxBa::retryUS));
}

static void testRxReordering()
{
    using namespace MtkAwdl;
    RxReorder<int> reorder;
    reorder.head = 4095;
    reorder.window = 8;
    std::vector<int> delivered, discarded;
    auto deliver = [&delivered](int value) { delivered.push_back(value); };
    auto discard = [&discarded](int value) { discarded.push_back(value); };
    reorder.receive(2, 0, 1000, deliver, discard);
    reorder.receive(3, 0, 1001, deliver, discard);
    assert(delivered.empty() && (discarded == std::vector<int>{3}));
    reorder.receive(1, 4095, 1002, deliver, discard);
    assert((delivered == std::vector<int>{1, 2}) && reorder.head == 1);
    reorder.receive(4, 3, 2000, deliver, discard);
    reorder.receive(5, 6, 3000, deliver, discard);
    reorder.expire(41999, deliver);
    assert(delivered.size() == 2);
    reorder.expire(42000, deliver);
    assert((delivered == std::vector<int>{1, 2, 4, 5}) && reorder.head == 7);
    uint8_t bar[20] = {0x84};
    ItlAWDL::write16(bar + 16, (5 << 12) | 4);
    ItlAWDL::write16(bar + 18, 12 << 4);
    uint8_t tid;
    uint16_t ssn;
    assert(parseBar(bar, sizeof(bar), tid, ssn) && tid == 5 && ssn == 12);
    assert(!parseBar(bar, 19, tid, ssn));
    reorder.receive(6, 12, 43000, deliver, discard);
    reorder.bar(ssn, 43001, deliver);
    assert(delivered.back() == 6 && reorder.head == 13);
    reorder.receive(7, 14, 44000, deliver, discard);
    reorder.receive(8, 90, 45000, deliver, discard);
    assert(delivered.back() == 7 && reorder.head == 83 && reorder.queued == 1);
    reorder.clear(discard);
    assert(discarded.back() == 8 && reorder.window == 0 && reorder.queued == 0);
}

static void testBandwidthAndSequence()
{
    const auto width = associatedWidth(157, CMD_CBW_80MHZ, 155);
    assert(width.mhz() == 80 && associatedWidth(36, CMD_CBW_80MHZ, 42).mhz() == 80);
    assert(associatedWidth(36, CMD_CBW_80MHZ, 155).mhz() == 20);
    assert(associatedWidth(6, CMD_CBW_40MHZ, 8).mhz() == 20);
    const uint8_t bytes[] = {
        1, 0, 0, 0, 2, 0, 16, 0, 157, 155, 0, 2, 2, 3, 1, 4, 1, 1, 0, 0
    };
    const auto rlm = makeRlmRequest(157, 2, 3, width);
    assert(sizeof(rlm) == sizeof(bytes) && !memcmp(&rlm, bytes, sizeof(bytes)));
    const auto forty = associatedWidth(161, CMD_CBW_40MHZ, 159);
    const auto rlm40 = makeRlmRequest(161, 2, 3, forty);
    assert(forty.mhz() == 40 && rlm40.rlm.secondaryOffset == 3 && rlm40.rlm.bandwidth == 1);

    constexpr uint32_t mcs9 = (1u << MT_TX_RATE_NSS_SHIFT) | (MT_PHY_TYPE_VHT << MT_TX_RATE_MODE_SHIFT) | 9;
    assert(fixedDataRate(mcs9, width) == ((mcs9 << 16) | MT_TXD6_LDPC | MT_TXD6_FIXED_BW | 2));
    assert((fixedDataRate(mcs9, forty) & MT_TXD6_BW) == 1);
    constexpr uint32_t ofdm = (MT_PHY_TYPE_OFDM << MT_TX_RATE_MODE_SHIFT) | 11;
    assert(fixedDataRate(ofdm, width) == ((ofdm << 16) | MT_TXD6_FIXED_BW));
    const uint32_t software = txSequenceFlags(MT_TXD3_BA_DISABLE, 4095, false);
    assert((software & MT_TXD3_SN_VALID) && (software & MT_TXD3_SEQ) == MT_TXD3_SEQ);
    assert(txSequenceFlags(software, 123, true) == MT_TXD3_BA_DISABLE);
    assert(!fixedBaRate(0, false));
    assert(fixedBaRate(0, true));
    assert(fixedBaRate(MT_TXD3_BA_DISABLE, false));

    assert(wtblProfileFromBootArg(-1) == WtblProfile::Baseline);
    assert(wtblProfileFromBootArg(4) == WtblProfile::Baseline);
    uint8_t wire[staRequestMax];
    for (int value = 0; value <= 3; ++value) {
        const auto profile = wtblProfileFromBootArg(value);
        const auto rlmProfile = makeRlmRequest(157, 2, 3, width, profile);
        assert(rlmProfile.rlm.bandwidth == 2 && rlmProfile.rlm.centerChannel == 155);
        assert(rlmProfile.rlm.secondaryOffset == (value < 2 ? 1 : 3));
        const auto createLength = buildStationRequest(wire, firstMac, 157, true,
            StationUpdate::Create, width, profile);
        if (value == 3) {
            assert(createLength == 88 && wire[2] == 2 && wire[28] == 13 &&
                wire[30] == 60 && wire[34] == 4);
            assert(wire[40] == WTBL_GENERIC && wire[60] == WTBL_RX &&
                wire[72] == WTBL_HDR_TRANS && wire[80] == WTBL_SMPS);
        } else {
            assert(createLength == 176 && wire[2] == 7 && wire[89] == 0);
            assert(wire[162] == 1 && wire[160] == (value ? 1 : 0));
            assert(wire[150] == (value ? 7 : 0) && wire[151] == (value ? 6 : 0));
        }
        const auto length = buildStationRequest(wire, firstMac, 157, true,
            StationUpdate::Associate, width, profile);
        assert(length == 92 && wire[2] == 6 && wire[88] == 2 && wire[89] == 0x12);
        assert(wire[35] == (value ? 0x1b : 0) && wire[60] == (value ? 0x63 : 0) &&
            wire[61] == 0);
        assert(wire[68] == (value ? 0x30 : 0x10) && wire[69] == 0 &&
            wire[70] == (value ? 0x80 : 0) && wire[71] == (value ? 3 : 0));
        assert(wire[72] == 0xfa && wire[74] == 0xfa);
    }

    // Bandwidth clamping: 80 MHz -> 80/40/20 across all four 20 MHz subchannels.
    assert(sanitizeMaxBw(20) == 20 && sanitizeMaxBw(40) == 40 && sanitizeMaxBw(80) == 80 && sanitizeMaxBw(99) == 80);
    const auto w80_149 = associatedWidth(149, CMD_CBW_80MHZ, 155);
    const auto w80_153 = associatedWidth(153, CMD_CBW_80MHZ, 155);
    const auto w80_157 = associatedWidth(157, CMD_CBW_80MHZ, 155);
    const auto w80_161 = associatedWidth(161, CMD_CBW_80MHZ, 155);
    assert(clampWidth(w80_149, 149, 40).code == CMD_CBW_40MHZ && clampWidth(w80_149, 149, 40).center == 151);
    assert(clampWidth(w80_153, 153, 40).code == CMD_CBW_40MHZ && clampWidth(w80_153, 153, 40).center == 151);
    assert(clampWidth(w80_157, 157, 40).code == CMD_CBW_40MHZ && clampWidth(w80_157, 157, 40).center == 159);
    assert(clampWidth(w80_161, 161, 40).code == CMD_CBW_40MHZ && clampWidth(w80_161, 161, 40).center == 159);
    assert(clampWidth(w80_157, 157, 20).code == CMD_CBW_20MHZ && clampWidth(w80_157, 157, 20).center == 157);
    assert(clampWidth(w80_157, 157, 80).code == CMD_CBW_80MHZ && clampWidth(w80_157, 157, 80).center == 155);
    assert(clampWidth(forty, 161, 80).code == CMD_CBW_40MHZ && clampWidth(forty, 161, 40).center == 159);
    assert(clampWidth(forty, 161, 20).code == CMD_CBW_20MHZ && clampWidth(forty, 161, 20).center == 161);

    // 6-bit independent capability mask verification (each bit isolated + combined).
    const ChannelWidth narrow20{CMD_CBW_20MHZ, 157};
    uint8_t baseWire[staRequestMax], maskWire[staRequestMax];
    // Bit 0: STA_REC_PHY.ampdu only (offset 35).
    assert(buildStationRequest(wire, firstMac, 157, true, StationUpdate::Create, width, StationConfig{capPhyAmpdu, false, false}) == 176);
    assert(wire[35] == 0x1b && wire[60] == 0 && wire[61] == 0);
    assert(wire[68] == 0x10 && wire[69] == 0 && wire[70] == 0 && wire[71] == 0);
    assert(wire[149] == 0 && wire[150] == 0 && wire[151] == 0 && wire[160] == 0);

    // Bit 1: STA_REC_HT LDPC + 20/40 (0x0003 on 80 MHz, 0x0001 on 20 MHz).
    assert(buildStationRequest(wire, firstMac, 157, true, StationUpdate::Create, width, StationConfig{capHtWideLdpc, false, false}) == 176);
    assert(wire[35] == 0 && wire[60] == 0x03 && wire[61] == 0 && wire[68] == 0x10 && wire[71] == 0 && wire[149] == 0);
    assert(buildStationRequest(wire, firstMac, 157, true, StationUpdate::Create, narrow20, StationConfig{capHtWideLdpc, false, false}) == 176);
    assert(wire[60] == 0x01 && wire[61] == 0);

    // Bit 2: STA_REC_HT SGI20/40 without RX STBC (0x0060 on 80 MHz, 0x0020 on 20 MHz).
    assert(buildStationRequest(wire, firstMac, 157, true, StationUpdate::Create, width, StationConfig{capHtSgiStbc, false, false}) == 176);
    assert(wire[35] == 0 && wire[60] == 0x60 && wire[61] == 0x00 && wire[68] == 0x10 && wire[149] == 0);
    assert(buildStationRequest(wire, firstMac, 157, true, StationUpdate::Create, narrow20, StationConfig{capHtSgiStbc, false, false}) == 176);
    assert(wire[60] == 0x20 && wire[61] == 0x00);

    // Bit 3: STA_REC_VHT conservative A-MPDU exp 3 (0x01800010).
    assert(buildStationRequest(wire, firstMac, 157, true, StationUpdate::Create, width, StationConfig{capVhtAmpdu3, false, false}) == 176);
    assert(wire[35] == 0 && wire[60] == 0 && wire[68] == 0x10 && wire[69] == 0 && wire[70] == 0x80 && wire[71] == 0x01 && wire[149] == 0);

    // Bit 4: STA_REC_VHT SGI80 + exp 7 without RX STBC (0x03800030 on 80 MHz, 0x03800010 on 20 MHz).
    assert(buildStationRequest(wire, firstMac, 157, true, StationUpdate::Create, width, StationConfig{capVhtSgiStbcExp7, false, false}) == 176);
    assert(wire[35] == 0 && wire[60] == 0 && wire[68] == 0x30 && wire[69] == 0x00 && wire[70] == 0x80 && wire[71] == 0x03 && wire[149] == 0);
    assert(buildStationRequest(wire, firstMac, 157, true, StationUpdate::Create, narrow20, StationConfig{capVhtSgiStbcExp7, false, false}) == 176);
    assert(wire[68] == 0x10 && wire[69] == 0x00 && wire[70] == 0x80 && wire[71] == 0x03);

    // Default station config enables AP-role BSS + STBC-free full capabilities + matchingSco.
    const auto defCfg = defaultStationConfig();
    assert(defCfg.capMask == capMaskAll && defCfg.matchingSco && !defCfg.twoStage && !defCfg.bssConnected && defCfg.apRole && defCfg.raFixed == 0);

    // Bit 5: WTBL_HT (ldpc/af/mm) + WTBL_VHT (ldpc) only.
    assert(buildStationRequest(wire, firstMac, 157, true, StationUpdate::Create, width, StationConfig{capWtblEnhanced, false, false}) == 176);
    assert(wire[35] == 0 && wire[60] == 0 && wire[68] == 0x10 && wire[71] == 0);
    assert(wire[148] == 1 && wire[149] == 1 && wire[150] == 7 && wire[151] == 6 && wire[160] == 1 && wire[162] == 1);

    // Byte-for-byte parity: capMask 0x00 == Baseline, capMask 0x3f (and 0xff) == Matched.
    const auto baseLen = buildStationRequest(baseWire, firstMac, 157, true, StationUpdate::Create, width, WtblProfile::Baseline);
    const auto mask0Len = buildStationRequest(maskWire, firstMac, 157, true, StationUpdate::Create, width, StationConfig{0, false, false});
    assert(baseLen == mask0Len && !memcmp(baseWire, maskWire, baseLen));
    const auto enhLen = buildStationRequest(baseWire, firstMac, 157, true, StationUpdate::Create, width, WtblProfile::Matched);
    const auto maskAllLen = buildStationRequest(maskWire, firstMac, 157, true, StationUpdate::Create, width, StationConfig{0xff, false, false});
    assert(enhLen == maskAllLen && !memcmp(baseWire, maskWire, enhLen));

    // Two-stage combined with partial capMask (e.g., bit 0 + bit 3) omits WTBL_HT/VHT on Create and applies capMask on Associate.
    assert(buildStationRequest(wire, firstMac, 157, true, StationUpdate::Create, width, StationConfig{capPhyAmpdu | capVhtAmpdu3, true, true}) == 88);
    assert(buildStationRequest(wire, firstMac, 157, true, StationUpdate::Associate, width, StationConfig{capPhyAmpdu | capVhtAmpdu3, true, true}) == 92);
    assert(wire[35] == 0x1b && wire[60] == 0 && wire[68] == 0x10 && wire[70] == 0x80 && wire[71] == 0x01);

    // RLM matchingSco flag directly.
    assert(makeRlmRequest(157, 2, 3, width, StationConfig{0, false, false}).rlm.secondaryOffset == 1);
    assert(makeRlmRequest(157, 2, 3, width, StationConfig{0, true, false}).rlm.secondaryOffset == 3);
    assert(makeRlmRequest(149, 2, 3, w80_149, StationConfig{0, false, false}).rlm.secondaryOffset == 1);
    assert(makeRlmRequest(149, 2, 3, w80_149, StationConfig{0, true, false}).rlm.secondaryOffset == 1);

    // bssConnected (conn_state=0, bcn=100, dtim=1, aid=1) and apRole (AP BSS + STA peer).
    const StationConfig connCfg{0x3b, true, true, true, false, 0};
    const auto connBss = makeBssRequest(firstMac, 157, 2, true, connCfg);
    assert(connBss.basic.conn_state == 0 && connBss.basic.bcn_interval == 100 && connBss.basic.dtim_period == 1);
    assert(connBss.basic.conn_type == (STA_TYPE_STA | NETWORK_INFRA));
    const auto disconnBss = makeBssRequest(firstMac, 157, 2, false, connCfg);
    assert(disconnBss.basic.conn_state == 1 && disconnBss.basic.bcn_interval == 0);
    assert(buildStationRequest(wire, firstMac, 157, true, StationUpdate::Create, width, connCfg) == 88);
    assert(wire[18] == 0 && wire[19] == 0);  // twoStage Create keeps aid=0
    assert(buildStationRequest(wire, firstMac, 157, true, StationUpdate::Associate, width, connCfg) == 92);
    assert(wire[18] == 1 && wire[19] == 0);  // Associate sets aid=1

    const StationConfig apCfg{0x3b, true, false, false, true, 0};
    const auto apBss = makeBssRequest(nextMac, 157, 2, true, apCfg);
    assert(apBss.basic.conn_type == (STA_TYPE_AP | NETWORK_INFRA) && apBss.basic.conn_state == 0);
    assert(!memcmp(apBss.basic.bssid, nextMac, 6));
    assert(buildStationRequest(wire, firstMac, 157, true, StationUpdate::Create, width, apCfg) == 176);
    assert(wire[12] == 1 && wire[14] == 1 && wire[18] == 1);  // STA_TYPE_STA | NETWORK_INFRA, aid=1

    // STA_REC_RA_UPDATE fixed rate request wire format.
    const auto ra9 = makeRaFixedRequest(157, true, width, 3);
    static_assert(sizeof(ra9.ra) == 25, "sta_rec_ra_fixed must match mt76 wire layout");
    assert(ra9.ra.tag == staRecRaUpdateTag && ra9.ra.len == 25 && ra9.ra.field == rateParamFixed);
    assert(ra9.ra.phy.type == MT_PHY_TYPE_VHT && ra9.ra.phy.bw == CMD_CBW_80MHZ &&
        ra9.ra.phy.ldpc == 1 && ra9.ra.phy.mcs == 9 && ra9.ra.phy.nss == 2 && ra9.ra.is_5g == 1);
    const auto ra40 = makeRaFixedRequest(157, true, forty, 3);
    assert(ra40.ra.phy.bw == CMD_CBW_40MHZ && ra40.ra.phy.mcs == 8);  // MCS9 clamped to MCS8 below 80 MHz
}

static void testBaWireFormat()
{
    const uint8_t wtblBytes[] = {
        1, 14, 1, 0, 1, 1, 0, 0,
        13, 0, 40, 0, 14, 2, 1, 0, 0, 0, 0, 0,
        8, 0, 28, 0, 0, 1, 0, 0, 0x56, 4, 1, 0, 32, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    const uint8_t staBytes[] = {
        1, 14, 1, 0, 1, 1, 0, 0,
        6, 0, 12, 0, 0, 1, 0, 1, 0x56, 4, 32, 0
    };
    const uint8_t rxWtblBytes[] = {
        1, 14, 1, 0, 1, 1, 0, 0,
        13, 0, 40, 0, 14, 2, 1, 0, 0, 0, 0, 0,
        8, 0, 28, 0, 5, 2, 0, 0, 0, 0, 0, 0, 32, 0,
        2, 1, 2, 3, 4, 5, 5, 0, 1, 0, 0, 0, 0, 0
    };
    const uint8_t rxStaBytes[] = {
        1, 14, 1, 0, 1, 1, 0, 0, 6, 0, 12, 0, 5, 2, 0, 32, 0x56, 4, 32, 0
    };
    const auto rxWtbl = makeWtblBa(0x456, 32, true, 5, firstMac);
    const auto rxSta = makeStaBa(0x456, 32, true, 5, true);
    assert(sizeof(rxWtbl) == sizeof(rxWtblBytes) && !memcmp(&rxWtbl, rxWtblBytes, sizeof(rxWtbl)));
    assert(sizeof(rxSta) == sizeof(rxStaBytes) && !memcmp(&rxSta, rxStaBytes, sizeof(rxSta)));
    const auto stopRx = makeStaBa(0x456, 32, false, 5, true);
    assert(stopRx.ba.tid == 5 && !stopRx.ba.ba_en && !stopRx.ba.winsize);
    auto wtbl = makeWtblBa(0x456, 32, true);
    auto sta = makeStaBa(0x456, 32, true);
    assert(sizeof(wtbl) == sizeof(wtblBytes) && !memcmp(&wtbl, wtblBytes, sizeof(wtbl)));
    assert(sizeof(sta) == sizeof(staBytes) && !memcmp(&sta, staBytes, sizeof(sta)));
    wtbl = makeWtblBa(0x456, 32, false);
    sta = makeStaBa(0x456, 32, false);
    assert(!wtbl.ba.ba_en && !wtbl.ba.sn && !wtbl.ba.ba_winsize);
    assert(!sta.ba.ba_en && !sta.ba.ssn && !sta.ba.winsize && !sta.ba.amsdu);
}

static void testWireFormat()
{
    const uint8_t activeBss[] = {
        1, 0, 0, 0,                           // BSS 1
        0, 0, 32, 0, 1, 1, 1, 0,            // BASIC, active, OMAC 1, band 0
        1, 0, 1, 0, 1, 2,                   // INFRA_STA, unconnected, WMM 2
        2, 1, 2, 3, 4, 5,                    // Peer MAC in the MCU BSS
        18, 0, 0, 0, 0, 0x31, 18, 0, 8, 0, 0, 0
    };
    auto bss = makeBssRequest(firstMac, 157, 2, true);
    assert(sizeof(bss) == sizeof(activeBss));
    assert(!memcmp(&bss, activeBss, sizeof(activeBss)));
    bss = makeBssRequest(firstMac, 157, 2, false);
    assert(!bss.basic.active && bss.basic.conn_state == 1);
    assert(!memcmp(bss.basic.bssid, firstMac, sizeof(firstMac)));

    const uint8_t rlmBytes[] = {
        1, 0, 0, 0, 2, 0, 16, 0, 157, 157, 0, 0, 2, 3, 1, 0, 0, 1, 0, 0
    };
    const auto rlm = makeRlmRequest(157, 2, 3);
    assert(sizeof(rlm) == sizeof(rlmBytes) && !memcmp(&rlm, rlmBytes, sizeof(rlmBytes)));
    const auto rlm2G = makeRlmRequest(6, 1, 1);
    assert(rlm2G.rlm.controlChannel == 6 && rlm2G.rlm.centerChannel == 6);
    assert(rlm2G.rlm.band == 0 && rlm2G.rlm.bandwidth == CMD_CBW_20MHZ);

    const uint8_t add[] = {
        1, 14, 7, 0, 1, 1, 0, 0,             // BSS, WCID, count, append, MUAR
        0, 0, 20, 0, 2, 0, 1, 0, 2, 1, 0, 0, 2, 1, 2, 3, 4, 5, 3, 0,
        0x15, 0, 12, 0, 0x50, 1, 0x38, 0, 0, 0xdc, 0, 0,
        1, 0, 16, 0, 0xc0, 0x3f, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0,
        9, 0, 8, 0, 0, 0, 0, 0,
        10, 0, 16, 0, 0x10, 0, 0, 0, 0xf5, 0xff, 0xf5, 0xff, 0, 0, 0, 0,
        7, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        13, 0, 84, 0, 14, 1, 6, 0, 0, 0, 0, 0,  // Nested WTBL reset and set
        0, 0, 20, 0, 2, 1, 2, 3, 4, 5, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
        1, 0, 12, 0, 0, 1, 1, 1, 0, 0, 0, 0,
        6, 0, 8, 0, 0, 0, 1, 0,              // No DS or RX translation
        2, 0, 12, 0, 1, 0, 0, 0, 0, 0, 0, 0,
        3, 0, 12, 0, 0, 0, 1, 0, 0, 0, 0, 0,
        13, 0, 8, 0, 0, 0, 0, 0
    };
    uint8_t wire[staRequestMax];
    assert(buildStationRequest(wire, firstMac, 157, true, StationUpdate::Create) == sizeof(add));
    assert(!memcmp(wire, add, sizeof(add)));
    assert(buildStationRequest(wire, firstMac, 6, false, StationUpdate::Create) == sizeof(add) - 28);
    assert(wire[2] == 6 && wire[47] == 0);    // No VHT and one HT stream.
    assert(wire[sizeof(add) - 28 - 14] == 0); // Safe minimal WTBL HT entry.

    // Association publishes state and PHY without the NEW flag or a WTBL reset.
    std::vector<uint8_t> associated(add, add + 92);
    associated[2] = 6;
    associated[26] = 1;
    associated[88] = 2;
    associated[89] = 0x10;
    assert(buildStationRequest(wire, firstMac, 157, true, StationUpdate::Associate) == associated.size());
    assert(!memcmp(wire, associated.data(), associated.size()));

    const uint8_t remove[] = {
        1, 14, 2, 0, 1, 1, 0, 0,
        0, 0, 20, 0, 2, 0, 1, 0, 0, 0, 0, 0, 2, 1, 2, 3, 4, 5, 1, 0,
        13, 0, 12, 0, 14, 1, 0, 0, 0, 0, 0, 0
    };
    assert(buildStationRequest(wire, firstMac, 157, true, StationUpdate::Remove) == sizeof(remove));
    assert(!memcmp(wire, remove, sizeof(remove)));
}

struct Firmware {
    enum Command { AddBss, Rlm, DeleteBss, AddSta, AssociateSta, DeleteSta, Drain, ClearBa, ClearRxBa, FlushRx };
    std::vector<Command> commands;
    uint8_t stationMac[6] = {}, bssMac[6] = {};
    bool bssActive = false;
    bool stationActive = false;
    bool ready = true;
    uint32_t bssError = 0, rlmError = 0, createError = 0, assocError = 0;
    uint32_t deleteStaError = 0, deleteBssError = 0, clearBaError = 0;

    bool canInstall(uint8_t) const { return ready; }
    uint32_t drain(uint32_t &inFlight) {
        commands.push_back(Drain);
        inFlight = 0;
        return 0;
    }
    uint32_t bss(const uint8_t *mac, uint8_t, bool enable) {
        assert(!stationActive);
        commands.push_back(enable ? AddBss : DeleteBss);
        if (enable)
            memcpy(bssMac, mac, sizeof(bssMac));
        else
            assert(!memcmp(bssMac, mac, sizeof(bssMac)));
        if (!enable && deleteBssError) return deleteBssError;
        bssActive = enable;
        return enable ? bssError : 0;
    }
    uint32_t clearBa(TxBa &ba) {
        assert(stationActive && !ba.active());
        commands.push_back(ClearBa);
        if (clearBaError) return clearBaError;
        ba.firmwareMayExist = false;
        return 0;
    }
    uint8_t bufferedTids = 0;
    void finishRxBa(uint8_t tid, uint8_t channel) {
        if (bufferedTids & (1u << tid)) {
            assert(channel == 157);
            commands.push_back(FlushRx);
            bufferedTids &= ~(1u << tid);
        }
    }
    uint32_t clearRxBa(RxBa &ba, const uint8_t *mac) {
        assert(stationActive && !ba.active && !memcmp(stationMac, mac, 6));
        assert(!bufferedTids);
        commands.push_back(ClearRxBa);
        ba.firmwareMayExist = false;
        return 0;
    }

    uint32_t rlm(uint8_t, ChannelWidth) {
        assert(bssActive && !stationActive);
        commands.push_back(Rlm);
        return rlmError;
    }
    uint32_t station(const uint8_t *mac, uint8_t, StationUpdate update, ChannelWidth = {}) {
        assert(bssActive && !memcmp(bssMac, mac, sizeof(bssMac)));
        if (update == StationUpdate::Create) {
            commands.push_back(AddSta);
            assert(!stationActive);
            memcpy(stationMac, mac, sizeof(stationMac));
            stationActive = true;
            return createError;
        }
        assert(stationActive && !memcmp(stationMac, mac, sizeof(stationMac)));
        if (update == StationUpdate::Associate) {
            commands.push_back(AssociateSta);
            return assocError;
        }
        commands.push_back(DeleteSta);
        if (deleteStaError) return deleteStaError;
        stationActive = false;
        return 0;
    }
};

static void testLifecycle()
{
    using Command = Firmware::Command;
    for (uint32_t i = 0; i < 65536; ++i) {
        const auto infra = infraNodeWcid(i);
        assert(infra > 0 && infra < wcid && infra != bmcWcid && infra != MWX_WTBL_RESERVED);
        assert(!slotConflict(0, 0, MWX_WTBL_RESERVED, infra));
    }
    assert(!slotConflict(0, 0, MWX_WTBL_RESERVED, MWX_WTBL_RESERVED));
    assert(slotConflict(1, 0, MWX_WTBL_RESERVED, 1));
    assert(slotConflict(0, 1, MWX_WTBL_RESERVED, 1));
    assert(slotConflict(0, 0, wcid, 1));
    assert(slotConflict(0, 0, bmcWcid, 1));
    assert(slotConflict(0, 0, MWX_WTBL_RESERVED, wcid));
    assert(slotConflict(0, 0, MWX_WTBL_RESERVED, bmcWcid));

    const uint8_t zero[6] = {};
    const uint8_t group[6] = {3};
    assert(!validPeerMac(nullptr) && !validPeerMac(zero) && !validPeerMac(group));
    assert(validPeerMac(firstMac));

    Slot slot = {};
    Firmware firmware;
    assert(!slot.replace(firmware, firstMac, 157));
    assert(slot.matches(firstMac, 157) && !slot.matches(nextMac, 157) && !slot.matches(firstMac, 149));
    assert(!slot.stickyForOtherPeer(157, 1000000));
    slot.lastDataAckUS = 1000000;
    assert(slot.stickyForOtherPeer(157, 3999999));
    assert(!slot.stickyForOtherPeer(157, 4000000));
    assert(!slot.stickyForOtherPeer(149, 2000000));
    slot.lastDataRxUS = 5000000;
    assert(slot.stickyForOtherPeer(157, 7999999) && !slot.stickyForOtherPeer(157, 8000000));
    slot.inFlight = 2;
    slot.ba.state = PeerBaState::Active;
    slot.ba.firmwareMayExist = true;
    slot.rxBa[0].active = slot.rxBa[0].firmwareMayExist = true;
    slot.rxBa[1].active = slot.rxBa[1].firmwareMayExist = true;
    slot.rxBa[1].tid = 1;
    firmware.bufferedTids = 3;
    assert(!slot.replace(firmware, nextMac, 157));
    assert((firmware.commands == std::vector<Command>{
        Firmware::AddBss, Firmware::Rlm, Firmware::AddSta, Firmware::AssociateSta,
        Firmware::FlushRx, Firmware::FlushRx, Firmware::Drain, Firmware::ClearBa,
        Firmware::ClearRxBa, Firmware::ClearRxBa, Firmware::DeleteSta, Firmware::DeleteBss,
        Firmware::AddBss, Firmware::Rlm, Firmware::AddSta, Firmware::AssociateSta}));
    assert(slot.matches(nextMac, 157) && slot.inFlight == 0);

    firmware.clearBaError = EIO;
    slot.ba.firmwareMayExist = true;
    firmware.commands.clear();
    const auto baFailure = slot.remove(firmware);
    assert(baFailure.step == FailStep::BaRemove && slot.ba.firmwareMayExist);
    assert((firmware.commands == std::vector<Command>{Firmware::Drain, Firmware::ClearBa}));
    firmware.clearBaError = 0;
    slot.ba.firmwareMayExist = false;

    firmware.deleteStaError = EIO;
    firmware.commands.clear();
    const auto failure = slot.replace(firmware, firstMac, 157);
    assert(failure.step == FailStep::StaRemove && failure.code == EIO);
    assert(!slot.active && slot.staMayExist && slot.bssMayExist);
    assert((firmware.commands == std::vector<Command>{Firmware::Drain, Firmware::DeleteSta}));
    firmware.deleteStaError = 0;
    // Reset and detach use the same idempotent retire path.
    assert(!slot.remove(firmware));
    assert(!slot.staMayExist && !slot.bssMayExist);
    firmware.commands.clear();
    assert(!slot.remove(firmware) && firmware.commands.empty());

}

static void testFailureSteps()
{
    // The high bit distinguishes this raw firmware sample from a BSD errno.
    constexpr uint32_t firmwareStatus = 0xc0000001;
    Slot slot = {};
    Firmware firmware;
    firmware.bssError = firmwareStatus;
    auto failure = slot.replace(firmware, firstMac, 157);
    assert(failure.step == FailStep::BssAdd && failure.code == firmwareStatus);
    assert(!slot.active && !slot.staMayExist && slot.bssMayExist);
    assert(!slot.remove(firmware));

    firmware.bssError = 0;
    firmware.rlmError = firmwareStatus;
    failure = slot.replace(firmware, firstMac, 157);
    assert(failure.step == FailStep::BssRlm && failure.code == firmwareStatus);
    assert(!slot.active && !slot.staMayExist && slot.bssMayExist);
    firmware.deleteBssError = EBUSY;
    const auto cleanup = slot.remove(firmware);
    assert(cleanup.step == FailStep::BssRemove && cleanup.code == EBUSY);
    firmware.deleteBssError = 0;
    assert(!slot.remove(firmware));

    firmware.rlmError = 0;
    firmware.createError = ETIMEDOUT;
    failure = slot.replace(firmware, firstMac, 157);
    assert(failure.step == FailStep::StaAdd && failure.code == ETIMEDOUT);
    assert(!slot.active && slot.staMayExist && slot.bssMayExist);
    assert(!slot.remove(firmware));

    firmware.createError = 0;
    firmware.assocError = firmwareStatus;
    failure = slot.replace(firmware, firstMac, 157);
    assert(failure.step == FailStep::StaAssociate && failure.code == firmwareStatus);
    assert(!slot.active && slot.staMayExist && slot.bssMayExist);
    assert(!slot.remove(firmware));
    assert(!firmware.bssActive && !firmware.stationActive);
}

int main()
{
    testBaActionAndState();
    testBaRetryBudget();
    testBaRxDiagnostics();
    testBandwidthAndSequence();
    testRxReordering();
    testBaWireFormat();
    testWireFormat();
    testLifecycle();
    testFailureSteps();
}
"""
with tempfile.TemporaryDirectory(prefix="mtk-awdl-wcid-test-") as path:
    source = Path(path, "test.cpp")
    exe = Path(path, "test")
    driver = (root / "SimpleMtkWlan/hal_mwx/MtkMwx.cpp").read_text()
    errors = driver.split("static void\nmwx_awdl_ba_error(", 1)[1].split("static void\nmwx_awdl_rx_ba_service", 1)[0]
    rx = driver.split("static bool\nmwx_awdl_ba_rx(", 1)[1].split("static int\nmwx_awdl_ba_send", 1)[0]
    responder = driver.split("static void\nmwx_awdl_rx_ba_service(", 1)[1].split("static void\nmwx_awdl_rx_deliver", 1)[0]
    source.write_text(body.replace("// BA_ERROR_AND_RX",
                                  "static void\nmwx_awdl_ba_error(" + errors +
                                  "static bool\nmwx_awdl_ba_rx(" + rx +
                                  "static void\nmwx_awdl_rx_ba_service(" + responder))
    subprocess.run(["clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
                    "-Wno-missing-field-initializers", "-fsanitize=address,undefined",
                    "-I", str(root / "include"), "-I", str(root / "SimpleMtkWlan/hal_mwx"), str(source), "-o", str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
