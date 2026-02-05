package com.juaneuse.sniffx.model;

import org.pcap4j.packet.Packet;

import java.time.LocalDateTime;
import static com.juaneuse.sniffx.util.HexUtils.toHexDump;

public class PacketInfo {

    private final Packet raw;
    private final LocalDateTime timestamp;
    private final String hexDump;

    public PacketInfo(Packet packet) {
        this.raw = packet;
        this.timestamp = LocalDateTime.now();
        this.hexDump = toHexDump(packet.getRawData());
    }

    public Packet getRawPacket() {
        return raw;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public String getHexDump() {
        return hexDump;
    }
}

