// Local, always-present fixed-channel schedule serialization. This is not peer
// synchronization or a transmit timer. Timing semantics cross-checked against
// seemoo-lab/owl src/sync.c and src/tx.c; independently implemented here.
#pragma once
#include "AWDLSyncPrefix.hpp"
#include "AWDLChannels.hpp"

namespace ItlAWDL {
// Encode the channel and timing at the supplied AW counter. The 73-byte payload includes
// the prefix, presence/counter fields, sixteen legacy slots and two zero padding bytes. Channel 149 uses the
// 5 GHz form of channel 6's 20 MHz flags: 0x2b has the 2.4 GHz band bit, 0x1b the
// 5 GHz one, as peers' own 5 GHz entries (0x1d) show. Inferred, not from a document.
inline BuildResult buildFixedScheduleAt(const SyncPrefix &settings, uint16_t counter,
        uint8_t *output, size_t available, size_t *written)
{
    if (!output || !written || !fixedScheduleChannel(settings.nextChannel))
        return BuildResult::Invalid;
    if (available < 73) return BuildResult::NoSpace;
    uint8_t payload[73] = {};
    size_t prefixLength;
    const auto result = buildSyncPrefix(settings, payload, sizeof(payload), &prefixLength);
    if (result != BuildResult::Ready) return result;
    payload[27] = 4;
    write16(payload+29, counter);
    payload[33] = 15; payload[34] = 1; payload[36] = 3;
    payload[37] = 0xff; payload[38] = 0xff;
    for (unsigned i = 0; i < 16; ++i) {
        const uint8_t slot = settings.nextChannel;
        payload[39+2*i] = legacySlotFlags(slot);
        payload[40+2*i] = slot;
    }
    for (unsigned i = 0; i < 73; ++i) output[i] = payload[i];
    *written = 73;
    return BuildResult::Ready;
}

inline BuildResult buildLocalFixedSchedule(const SyncPrefix &settings,
        uint64_t epochUS, uint64_t nowUS, uint16_t initialAW,
        uint8_t *output, size_t available, size_t *written)
{
    if (nowUS < epochUS || (initialAW & 3) ||
        settings.masterChannel != settings.nextChannel ||
        !settings.awPeriod || settings.awPeriod > 16383 ||
        settings.commonLength > settings.awPeriod)
        return BuildResult::Invalid;
    const uint64_t elapsedTU = (nowUS - epochUS) / 1024;
    const uint32_t extendedTU = uint32_t(settings.awPeriod) * 4;
    const uint32_t phaseTU = uint32_t(elapsedTU % extendedTU);
    const uint16_t counter = uint16_t((elapsedTU / settings.awPeriod + initialAW) & 0xffff);
    SyncPrefix p = settings;
    p.txDownCounter = uint16_t(extendedTU - phaseTU);
    p.remainingAW = phaseTU < p.commonLength ? uint16_t(p.commonLength - phaseTU) : 0;
    return buildFixedScheduleAt(p, counter, output, available, written);
}
} // namespace ItlAWDL
