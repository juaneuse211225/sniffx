package com.juaneuse.sniffx.model;

import com.juaneuse.sniffx.parser.ParsedPacket;
import com.juaneuse.sniffx.sniffer.PacketParserManager;
import org.pcap4j.packet.Packet;

import java.time.LocalDateTime;
import static com.juaneuse.sniffx.util.HexUtils.toHexDump;

public class PacketInfo {

    private final ParsedPacket parsed;
    private final Packet raw;

    public PacketInfo(Packet packet) {
        this.raw = packet;
        this.parsed = PacketParserManager.parse(packet, packet.length());
        this.parsed.timestamp = LocalDateTime.now();
        this.parsed.hexDump = toHexDump(packet.getRawData());
    }

    public ParsedPacket getParsed() {
        return parsed;
    }

    public Packet getRawPacket() {
        return raw;
    }
}

