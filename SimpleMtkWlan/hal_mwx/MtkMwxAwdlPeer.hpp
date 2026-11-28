#pragma once

#include <HAL/MtkAwdlBa.hpp>

// Uses the Connac2 MCU wire records from if_mwxreg.h.
namespace MwxAwdlPeer {

constexpr uint16_t wcid = MWX_WTBL_STA - 1;
constexpr uint16_t bmcWcid = MWX_WTBL_RESERVED - 1;
constexpr uint8_t bssIndex = HW_BSSID_1;
// Connac2 uses the local STA role for an inactive client BSS and the
// complementary AP role for its peer record, including P2P client peers.
constexpr uint32_t bssConnectionType = STA_TYPE_STA | NETWORK_INFRA;
constexpr uint32_t peerConnectionType = STA_TYPE_AP | NETWORK_INFRA;

static_assert(wcid > 1 && wcid < bmcWcid && bmcWcid < MWX_WTBL_RESERVED,
    "AWDL peer and BSS WCIDs must occupy separate reserved entries");
static_assert(bssIndex < MWX_MAX_INTERFACES, "AWDL BSS index exceeds firmware range");

constexpr uint16_t infraNodeWcid(uint32_t ordinal) {
    return 1 + ordinal % (wcid - 1);
}

constexpr bool slotConflict(uint8_t infraBss, uint8_t infraOmac,
                            uint16_t infraVifWcid, uint16_t infraApWcid) {
    return infraBss == bssIndex || infraOmac == HW_BSSID_1 ||
        infraVifWcid == wcid || infraVifWcid == bmcWcid ||
        infraApWcid == wcid || infraApWcid == bmcWcid;
}

enum class FailStep : uint8_t {
    None = 0, GuardConflict = 1, BssAdd = 2, StaAdd = 3, StaRemove = 4,
    BssRemove = 5, DevUpdate = 6, BssRlm = 7, FirmwareCoredump = 8, StaAssociate = 9, BaRemove = 10
};

struct Failure {
    FailStep step = FailStep::None;
    uint32_t code = 0;
    explicit operator bool() const { return code != 0; }
};

inline bool validPeerMac(const uint8_t *mac) {
    constexpr uint8_t zero[IEEE80211_ADDR_LEN] = {};
    return mac && !(mac[0] & 1) && memcmp(mac, zero, sizeof(zero)) != 0;
}

struct BssRequest {
    uint8_t index;
    uint8_t reserved[3];
    mt76_connac_bss_basic_tlv basic;
} __packed;

inline BssRequest makeBssRequest(const uint8_t *peerMac, uint8_t channel, uint8_t wmm, bool enable) {
    BssRequest req = {};
    req.index = bssIndex;
    req.basic.tag = htole16(UNI_BSS_INFO_BASIC);
    req.basic.len = htole16(sizeof(req.basic));
    req.basic.active = enable;
    req.basic.omac_idx = HW_BSSID_1;
    req.basic.hw_bss_idx = HW_BSSID_1;
    req.basic.conn_type = htole32(bssConnectionType);
    // Allocate the BSS without asserting a beacon-synchronized association.
    req.basic.conn_state = 1;
    req.basic.wmm_idx = wmm;
    memcpy(req.basic.bssid, peerMac, sizeof(req.basic.bssid));
    req.basic.bmc_tx_wlan_idx = htole16(bmcWcid);
    req.basic.sta_idx = htole16(bmcWcid);
    req.basic.phymode = channel >= 36 ? 0x31 : 0x0e;  // A/AN/AC or B/G/GN.
    req.basic.nonht_basic_phy = htole16(channel >= 36 ? PHY_TYPE_BIT_OFDM :
        PHY_TYPE_BIT_HR_DSSS | PHY_TYPE_BIT_ERP);
    return req;
}

struct ChannelWidth {
    uint8_t code = CMD_CBW_20MHZ;
    uint8_t center = 0;

    bool operator!=(const ChannelWidth &other) const {
        return code != other.code || center != other.center;
    }
    uint8_t mhz() const { return code == CMD_CBW_80MHZ ? 80 : code == CMD_CBW_40MHZ ? 40 : 20; }
};

inline ChannelWidth associatedWidth(uint8_t primary, uint8_t code, uint8_t center) {
    const int offset = int(primary) - int(center);
    if (primary >= 36 && center >= 36 &&
        ((code == CMD_CBW_80MHZ && (offset == 6 || offset == 2 || offset == -2 || offset == -6)) ||
         (code == CMD_CBW_40MHZ && (offset == 2 || offset == -2))))
        return {code, center};
    return {CMD_CBW_20MHZ, primary};
}

inline uint8_t sanitizeMaxBw(int value) {
    return value == 20 ? 20 : value == 40 ? 40 : 80;
}

inline ChannelWidth clampWidth(ChannelWidth associated, uint8_t primary, uint8_t maxBwMhz) {
    if (!primary || maxBwMhz <= 20 || associated.code == CMD_CBW_20MHZ)
        return {CMD_CBW_20MHZ, primary};
    if (maxBwMhz <= 40 && associated.code == CMD_CBW_80MHZ) {
        const uint8_t center40 = primary < associated.center ?
            uint8_t(associated.center - 4) : uint8_t(associated.center + 4);
        return associatedWidth(primary, CMD_CBW_40MHZ, center40);
    }
    return associated;
}

inline uint32_t fixedDataRate(uint32_t rate, ChannelWidth width) {
    const auto mode = (rate & MT_TX_RATE_MODE_MASK) >> MT_TX_RATE_MODE_SHIFT;
    const auto base = MT_TXD6_FIXED_BW | ((rate << MT_TXD6_TX_RATE_SHIFT) & MT_TXD6_TX_RATE_MASK);
    return mode == MT_PHY_TYPE_VHT ? base | MT_TXD6_LDPC | width.code : base;
}

enum class WtblProfile : uint8_t { Baseline, Matched, MatchingSco, TwoStage };

inline WtblProfile wtblProfileFromBootArg(int value) {
    return value >= 0 && value <= int(WtblProfile::TwoStage) ? WtblProfile(value) : WtblProfile::Baseline;
}

// 6-bit independent STA/WTBL capability mask (splits legacy `enhanced`).
constexpr uint8_t capPhyAmpdu       = 1u << 0;  // 0x01: STA_REC_PHY.ampdu = 0x1b
constexpr uint8_t capHtWideLdpc     = 1u << 1;  // 0x02: STA_REC_HT LDPC + 20/40
constexpr uint8_t capHtSgiStbc      = 1u << 2;  // 0x04: STA_REC_HT SGI20/40 + RX STBC 1
constexpr uint8_t capVhtAmpdu3      = 1u << 3;  // 0x08: STA_REC_VHT conservative A-MPDU exp 3
constexpr uint8_t capVhtSgiStbcExp7 = 1u << 4;  // 0x10: STA_REC_VHT SGI80 + RX STBC 1 + exp 7
constexpr uint8_t capWtblEnhanced   = 1u << 5;  // 0x20: WTBL_HT (ldpc/af/mm) + WTBL_VHT (ldpc)
constexpr uint8_t capMaskAll        = 0x3f;

struct StationConfig {
    uint8_t capMask = 0;
    bool matchingSco = false;
    bool twoStage = false;

    bool operator==(const StationConfig &other) const {
        return capMask == other.capMask && matchingSco == other.matchingSco &&
            twoStage == other.twoStage;
    }
    bool operator!=(const StationConfig &other) const { return !(*this == other); }
};

inline StationConfig stationConfigFromProfile(WtblProfile profile) {
    switch (profile) {
    case WtblProfile::Matched:     return {capMaskAll, false, false};
    case WtblProfile::MatchingSco: return {capMaskAll, true, false};
    case WtblProfile::TwoStage:    return {capMaskAll, true, true};
    case WtblProfile::Baseline:
    default:                       return {0, false, false};
    }
}

struct RlmRequest {
    uint8_t index;
    uint8_t reserved[3];
    struct {
        uint16_t tag, len;
        uint8_t controlChannel, centerChannel, centerChannel2, bandwidth;
        uint8_t txStreams, rxStreams, shortSlot, htOpInfo;
        uint8_t secondaryOffset, band, reserved[2];
    } __packed rlm;
} __packed;

inline RlmRequest makeRlmRequest(uint8_t channel, uint8_t txStreams, uint8_t rxMask,
                                 ChannelWidth width, StationConfig config) {
    RlmRequest request = {};
    request.index = bssIndex;
    request.rlm.tag = htole16(UNI_BSS_INFO_RLM);
    request.rlm.len = htole16(sizeof(request.rlm));
    request.rlm.controlChannel = channel;
    request.rlm.centerChannel = width.center ? width.center : channel;
    request.rlm.bandwidth = width.code;
    if (width.code != CMD_CBW_20MHZ) {
        const int delta = int(channel) - int(width.center);
        const bool above = width.code == CMD_CBW_40MHZ ? delta < 0 : (delta == -6 || delta == 2);
        request.rlm.secondaryOffset = config.matchingSco ?
            (delta < 0 ? 1 : delta > 0 ? 3 : 0) : (above ? 1 : 3);
        request.rlm.htOpInfo = 4;
    }
    request.rlm.txStreams = txStreams;
    request.rlm.rxStreams = rxMask;
    request.rlm.shortSlot = 1;
    request.rlm.band = channel >= 36;
    return request;
}

inline RlmRequest makeRlmRequest(uint8_t channel, uint8_t txStreams, uint8_t rxMask,
                                 ChannelWidth width = {}, WtblProfile profile = WtblProfile::Baseline) {
    return makeRlmRequest(channel, txStreams, rxMask, width, stationConfigFromProfile(profile));
}

constexpr size_t staRequestMax = sizeof(sta_req_hdr) + sizeof(sta_rec_basic) +
    sizeof(sta_rec_phy) + sizeof(sta_rec_ra_info) + sizeof(sta_rec_ht_v1) +
    sizeof(sta_rec_vht_v1) + sizeof(sta_rec_state) + sizeof(sta_rec_wtbl) +
    sizeof(wtbl_generic) + sizeof(wtbl_rx) + sizeof(wtbl_hdr_trans) +
    sizeof(wtbl_ht) + sizeof(wtbl_vht) + sizeof(wtbl_smps);

template <typename Record>
inline void append(uint8_t *&out, const Record &record) {
    memcpy(out, &record, sizeof(record));
    out += sizeof(record);
}

enum class StationUpdate : uint8_t { Create, Associate, Remove };

inline size_t buildStationRequest(uint8_t (&buffer)[staRequestMax], const uint8_t *mac,
                                  uint8_t channel, bool twoStreams, StationUpdate update,
                                  ChannelWidth width, StationConfig config) {
    const bool enable = update != StationUpdate::Remove;
    const bool create = update == StationUpdate::Create;
    const bool associate = update == StationUpdate::Associate;
    const bool vht = channel >= 36;
    const bool mcs9 = width.code == CMD_CBW_80MHZ;
    const uint8_t caps = config.capMask & capMaskAll;
    const bool fullStation = enable && !(create && config.twoStage);
    const bool wtblPhy = create && !config.twoStage;
    auto *out = buffer;
    sta_req_hdr header = {};
    header.bss_idx = bssIndex;
    header.wlan_idx_lo = wcid & 0xff;
    header.wlan_idx_hi = wcid >> 8;
    header.tlv_num = htole16(1 + (fullStation ? 4 + unsigned(vht) : 0) + unsigned(!associate));
    header.is_tlv_append = 1;
    header.muar_idx = HW_BSSID_1;
    append(out, header);

    sta_rec_basic basic = {htole16(STA_REC_BASIC), htole16(sizeof(basic))};
    basic.conn_type = htole32(peerConnectionType);
    basic.conn_state = enable ? CONN_STATE_PORT_SECURE : CONN_STATE_DISCONNECT;
    basic.qos = enable;
    memcpy(basic.peer_addr, mac, sizeof(basic.peer_addr));
    basic.extra_info = htole16(EXTRA_INFO_VER | (create ? EXTRA_INFO_NEW : 0));
    append(out, basic);

    if (fullStation) {
        // Open peer profile used by both fixed-rate TX and firmware rate control.
        sta_rec_phy phy = {htole16(STA_REC_PHY), htole16(sizeof(phy))};
        phy.basic_rate = htole16(0x0150);
        phy.phy_type = PHY_TYPE_BIT_HT | (vht ? PHY_TYPE_BIT_OFDM | PHY_TYPE_BIT_VHT :
            PHY_TYPE_BIT_HR_DSSS | PHY_TYPE_BIT_ERP);
        phy.ampdu = (caps & capPhyAmpdu) ? 0x1b : 0;  // HT A-MPDU exponent 3 and minimum MPDU spacing.
        phy.rcpi = 0xdc;
        append(out, phy);
        sta_rec_ra_info ra = {htole16(STA_REC_RA), htole16(sizeof(ra))};
        ra.legacy = htole16(RA_LEGACY_OFDM | (vht ? 0 : RA_LEGACY_CCK));
        ra.rx_mcs_bitmask[0] = 0xff;
        ra.rx_mcs_bitmask[1] = twoStreams ? 0xff : 0;
        append(out, ra);
        sta_rec_ht_v1 ht = {htole16(STA_REC_HT), htole16(sizeof(ht))};
        uint16_t htCap = 0;
        if (caps & capHtWideLdpc)
            htCap |= 0x0001u | (width.code != CMD_CBW_20MHZ ? 0x0002u : 0u);  // LDPC, 20/40.
        if (caps & capHtSgiStbc)
            htCap |= 0x0020u | 0x0100u | (width.code != CMD_CBW_20MHZ ? 0x0040u : 0u);  // SGI20, RX STBC 1, SGI40.
        ht.ht_cap = htole16(htCap);
        append(out, ht);
        if (vht) {
            sta_rec_vht_v1 vhtRec = {htole16(STA_REC_VHT), htole16(sizeof(vhtRec))};
            // MCS 0–9 at 80 MHz and MCS 0–8 on the narrower profiles.
            uint32_t vhtCap = (1u << 4);
            if (caps & capVhtSgiStbcExp7)
                vhtCap |= (1u << 8) | (7u << 23) | (mcs9 ? (1u << 5) : 0u);
            else if (caps & capVhtAmpdu3)
                vhtCap |= (3u << 23);
            vhtRec.vht_cap = htole32(vhtCap);
            vhtRec.vht_rx_mcs_map = vhtRec.vht_tx_mcs_map = htole16(mcs9 ?
                (twoStreams ? 0xfffa : 0xfffe) : (twoStreams ? 0xfff5 : 0xfffd));
            append(out, vhtRec);
        }
        sta_rec_state state = {htole16(STA_REC_STATE), htole16(sizeof(state))};
        state.state = associate ? 2 : 0;
        state.vht_opmode = associate && vht ? width.code | (twoStreams ? 0x10 : 0) : 0;
        append(out, state);
    }

    // The association update keeps the WTBL installed by the create command.
    if (associate) return size_t(out - buffer);

    sta_rec_wtbl wtbl = {htole16(STA_REC_WTBL), htole16(sizeof(wtbl))};
    wtbl.wlan_idx_lo = header.wlan_idx_lo;
    wtbl.wlan_idx_hi = header.wlan_idx_hi;
    wtbl.operation = WTBL_RESET_AND_SET;
    if (enable) {
        wtbl.tlv_num = htole16(4 + (wtblPhy ? 1 + unsigned(vht) : 0));
        wtbl.len = htole16(sizeof(wtbl) + sizeof(wtbl_generic) + sizeof(wtbl_rx) +
            sizeof(wtbl_hdr_trans) + sizeof(wtbl_smps) +
            (wtblPhy ? sizeof(wtbl_ht) + (vht ? sizeof(wtbl_vht) : 0) : 0));
    }
    append(out, wtbl);
    if (enable) {
        wtbl_generic generic = {htole16(WTBL_GENERIC), htole16(sizeof(generic))};
        memcpy(generic.peer_addr, mac, sizeof(generic.peer_addr));
        generic.muar_idx = HW_BSSID_1;
        generic.qos = 1;
        append(out, generic);
        wtbl_rx rx = {htole16(WTBL_RX), htole16(sizeof(rx))};
        rx.rca1 = rx.rca2 = rx.rv = 1;
        append(out, rx);
        wtbl_hdr_trans translation = {htole16(WTBL_HDR_TRANS), htole16(sizeof(translation))};
        translation.no_rx_trans = 1;
        append(out, translation);
        if (wtblPhy) {
            const bool wtblEnhanced = (caps & capWtblEnhanced) != 0;
            wtbl_ht ht = {htole16(WTBL_HT), htole16(sizeof(ht))};
            ht.ht = 1;
            if (wtblEnhanced) {
                ht.ldpc = 1;
                ht.af = vht ? 7 : 3;
                ht.mm = 6;
            }
            append(out, ht);
            if (vht) {
                wtbl_vht vhtWtbl = {htole16(WTBL_VHT), htole16(sizeof(vhtWtbl))};
                vhtWtbl.vht = 1;
                vhtWtbl.ldpc = wtblEnhanced;
                append(out, vhtWtbl);
            }
        }
        wtbl_smps smps = {htole16(WTBL_SMPS), htole16(sizeof(smps))};
        append(out, smps);
    }
    return size_t(out - buffer);
}

inline size_t buildStationRequest(uint8_t (&buffer)[staRequestMax], const uint8_t *mac,
                                  uint8_t channel, bool twoStreams, StationUpdate update,
                                  ChannelWidth width = {}, WtblProfile profile = WtblProfile::Baseline) {
    return buildStationRequest(buffer, mac, channel, twoStreams, update, width,
        stationConfigFromProfile(profile));
}

using MtkAwdl::PeerBaState;

struct TxBa {
    static constexpr uint64_t timeoutUS = 400000;
    static constexpr uint64_t retryUS = 1000000;
    static constexpr uint64_t prepareUS = 3000;
    static constexpr uint64_t commitUS = 10000;
    static constexpr uint8_t maxAttempts = 4;  // Initial request plus three retries.
    PeerBaState state;
    uint8_t token, attempts;
    uint16_t nextSequence, ssn, window;
    uint32_t inFlight;
    uint64_t deadlineUS, nextRequestUS, prepareUntilUS;
    bool firmwareMayExist, sendDelba, retryAllowed, hardwareSequence;

    bool active() const { return state == PeerBaState::Active; }
    bool requested() const { return state == PeerBaState::Requested; }
    bool accepted() const { return requested() && window != 0; }
    bool expired(uint64_t now) const { return requested() && !firmwareMayExist && now >= deadlineUS; }

    // During negotiation, non-QoS data can continue without consuming TID 0 SSNs.
    bool holdData() const { return accepted() && !firmwareMayExist; }

    bool canRequest(uint64_t now) const {
        return (state == PeerBaState::Idle || (state == PeerBaState::Failed && retryAllowed)) &&
            !firmwareMayExist && attempts < maxAttempts && now >= nextRequestUS;
    }

    void submitted() { nextSequence = (nextSequence + 1) & 0xfff; }

    void request(uint8_t dialogToken, uint64_t now) {
        state = PeerBaState::Requested;
        token = dialogToken;
        ssn = nextSequence;
        deadlineUS = now + timeoutUS;
        nextRequestUS = now + retryUS;
        prepareUntilUS = 0;
        ++attempts;
    }

    bool accept(const MtkAwdl::BaResponse &response, uint64_t now) {
        if (!requested() || accepted() || response.token != token ||
            response.status || !response.compatible())
            return false;
        window = response.window() < MtkAwdl::baWindow ? response.window() : MtkAwdl::baWindow;
        deadlineUS = now + commitUS;
        return true;
    }

    bool activate(uint32_t firmwareError) {
        if (firmwareError || !accepted() || !firmwareMayExist) return false;
        hardwareSequence = true;
        state = PeerBaState::Active;
        return true;
    }

    void stop(PeerBaState nextState, bool notify = false) {
        state = nextState;
        window = 0;
        sendDelba = notify;
        retryAllowed = false;
        prepareUntilUS = 0;
    }

    void onRecipientDelba(uint64_t now) {
        const bool wasActive = active();
        stop(PeerBaState::Idle, false);
        if (wasActive)
            attempts = 0;
        nextRequestUS = now + retryUS;
    }
};

constexpr uint8_t rxBaTids = 8;

struct RxBa {
    static constexpr uint64_t duplicateWindowUS = 500000;
    MtkAwdl::BaRequest pendingRequest;
    uint16_t ssn, window;
    uint8_t tid, token;
    bool pending, active, firmwareMayExist, stopping, unsupported;
    uint64_t setupUS;

    bool matchesDuplicate(const MtkAwdl::BaRequest &request, uint16_t reorderHead, uint64_t now) const {
        return active && ssn == request.ssn && token == request.token &&
            MtkAwdl::RxReorder<void *>::distance(reorderHead, request.ssn) < window &&
            setupUS && now >= setupUS && now - setupUS < duplicateWindowUS;
    }
};

inline uint32_t dataBaFlags(uint32_t txd3, bool dedicatedPeer, const TxBa &ba,
                            bool qosTidZero, uint32_t rateMode, bool fixedBa = false) {
    const bool rateOk = !fixedBa || rateMode == MT_PHY_TYPE_HT || rateMode == MT_PHY_TYPE_VHT;
    const bool aggregate = dedicatedPeer && ba.active() && ba.firmwareMayExist && qosTidZero && rateOk;
    return aggregate ? txd3 & ~MT_TXD3_BA_DISABLE : txd3 | MT_TXD3_BA_DISABLE;
}

inline bool fixedBaRate(uint32_t txd3, bool fixedBa) {
    return fixedBa || (txd3 & MT_TXD3_BA_DISABLE);
}

inline uint32_t txSequenceFlags(uint32_t txd3, uint16_t sequence, bool hardwareSequence) {
    txd3 &= ~(MT_TXD3_SN_VALID | MT_TXD3_SEQ);
    return hardwareSequence ? txd3 : txd3 | MT_TXD3_SN_VALID | (uint32_t(sequence & 0xfff) << 16);
}

inline sta_req_hdr baRequestHeader() {
    sta_req_hdr header = {};
    header.bss_idx = bssIndex;
    header.wlan_idx_lo = wcid & 0xff;
    header.wlan_idx_hi = wcid >> 8;
    header.tlv_num = htole16(1);
    header.is_tlv_append = 1;
    header.muar_idx = HW_BSSID_1;
    return header;
}

struct WtblBaRequest {
    sta_req_hdr header;
    sta_rec_wtbl wtbl;
    wtbl_ba ba;
} __packed;

inline WtblBaRequest makeWtblBa(uint16_t ssn, uint16_t window, bool enable,
                                uint8_t tid = 0, const uint8_t *recipientPeer = nullptr) {
    WtblBaRequest request = {};
    request.header = baRequestHeader();
    request.wtbl.tag = htole16(STA_REC_WTBL);
    request.wtbl.len = htole16(sizeof(request.wtbl) + sizeof(request.ba));
    request.wtbl.wlan_idx_lo = request.header.wlan_idx_lo;
    request.wtbl.wlan_idx_hi = request.header.wlan_idx_hi;
    request.wtbl.operation = WTBL_SET;
    request.wtbl.tlv_num = htole16(1);
    request.ba.tag = htole16(WTBL_BA);
    request.ba.len = htole16(sizeof(request.ba));
    request.ba.tid = tid;
    if (recipientPeer) {
        request.ba.ba_type = MT_BA_TYPE_RECIPIENT;
        memcpy(request.ba.peer_addr, recipientPeer, sizeof(request.ba.peer_addr));
        request.ba.rst_ba_tid = tid;
        request.ba.rst_ba_sel = 0;  // RST_BA_MAC_TID_MATCH.
        request.ba.rst_ba_sb = 1;
    } else {
        request.ba.ba_type = MT_BA_TYPE_ORIGINATOR;
        request.ba.ba_en = enable;
        request.ba.sn = htole16(enable ? ssn : 0);
    }
    request.ba.ba_winsize = htole16(enable ? window : 0);
    return request;
}

struct StaBaRequest {
    sta_req_hdr header;
    sta_rec_ba ba;
} __packed;

inline StaBaRequest makeStaBa(uint16_t ssn, uint16_t window, bool enable,
                              uint8_t tid = 0, bool recipient = false) {
    StaBaRequest request = {};
    request.header = baRequestHeader();
    request.ba.tag = htole16(STA_REC_BA);
    request.ba.len = htole16(sizeof(request.ba));
    request.ba.tid = tid;
    request.ba.ba_type = recipient ? MT_BA_TYPE_RECIPIENT : MT_BA_TYPE_ORIGINATOR;
    request.ba.ba_en = enable ? 1u << tid : 0;
    request.ba.ssn = htole16(enable ? ssn : 0);
    request.ba.winsize = htole16(enable ? window : 0);
    return request;
}

struct Slot {
    uint8_t mac[IEEE80211_ADDR_LEN];
    uint8_t channel;
    ChannelWidth width;
    bool bssMayExist;
    bool staMayExist;
    bool active;
    uint32_t inFlight;
    TxBa ba;
    RxBa rxBa[rxBaTids];
    uint64_t lastDataAckUS, lastDataRxUS;

    void stopRxBa() {
        for (auto &session : rxBa)
            session.active = session.pending = false;
    }

    static constexpr uint64_t stickyGraceUS = 3000000;

    bool matches(const uint8_t *destination, uint8_t currentChannel) const {
        return active && currentChannel == channel && memcmp(mac, destination, sizeof(mac)) == 0;
    }

    bool stickyForOtherPeer(uint8_t currentChannel, uint64_t nowUS) const {
        if (!active || currentChannel != channel)
            return false;
        const uint64_t lastData = lastDataAckUS > lastDataRxUS ? lastDataAckUS : lastDataRxUS;
        return lastData && nowUS >= lastData && nowUS - lastData < stickyGraceUS;
    }

    // MCU commands may time out after applying the update. Keep ownership until
    // a confirmed delete or a firmware reload, including on partial setup.
    template <typename Firmware>
    Failure remove(Firmware &firmware) {
        active = false;
        ba.stop(PeerBaState::Idle);
        stopRxBa();
        for (uint8_t tid = 0; tid < rxBaTids; ++tid)
            firmware.finishRxBa(tid, channel);
        if (staMayExist) {
            const auto drainError = firmware.drain(inFlight);
            if (drainError) return {FailStep::StaRemove, drainError};
            if (ba.firmwareMayExist) {
                const auto error = firmware.clearBa(ba);
                if (error) return {FailStep::BaRemove, error};
            }
            for (auto &session : rxBa) {
                if (session.firmwareMayExist) {
                    const auto error = firmware.clearRxBa(session, mac);
                    if (error) return {FailStep::BaRemove, error};
                }
            }
            const auto error = firmware.station(mac, channel, StationUpdate::Remove);
            if (error) return {FailStep::StaRemove, error};
            staMayExist = false;
        }
        if (bssMayExist) {
            const auto error = firmware.bss(mac, channel, false);
            if (error) return {FailStep::BssRemove, error};
            bssMayExist = false;
        }
        channel = 0;
        return {};
    }

    template <typename Firmware>
    Failure replace(Firmware &firmware, const uint8_t *destination, uint8_t newChannel, ChannelWidth newWidth = {}) {
        const auto cleanup = remove(firmware);
        if (cleanup || !newChannel || !firmware.canInstall(newChannel))
            return cleanup;

        ba = {};
        for (auto &session : rxBa)
            session = {};
        lastDataAckUS = lastDataRxUS = 0;
        channel = newChannel;
        width = newWidth;
        memcpy(mac, destination, sizeof(mac));
        bssMayExist = true;
        const auto bssError = firmware.bss(mac, channel, true);
        if (bssError) return {FailStep::BssAdd, bssError};
        if (!firmware.canInstall(channel)) return {};
        const auto rlmError = firmware.rlm(channel, width);
        if (rlmError) return {FailStep::BssRlm, rlmError};
        if (!firmware.canInstall(channel)) return {};
        staMayExist = true;
        const auto staError = firmware.station(mac, channel, StationUpdate::Create, width);
        if (staError) return {FailStep::StaAdd, staError};
        if (!firmware.canInstall(channel)) return {};
        const auto assocError = firmware.station(mac, channel, StationUpdate::Associate, width);
        if (assocError) return {FailStep::StaAssociate, assocError};
        active = firmware.canInstall(channel);
        return {};
    }
};

}  // namespace MwxAwdlPeer
