package com.juaneuse.sniffx.parser;

import org.pcap4j.packet.IcmpV6CommonPacket;
import org.pcap4j.packet.Packet;

/**
 *
 * @author juaneuse
 */
public class IcmpV6Parser extends PacketParser {

    @Override
    public boolean soporta(Packet packet) {
        return packet.contains(IcmpV6CommonPacket.class);
    }

    @Override
    public void parse(Packet packet, ParsedPacket out) {
        out.protocol = "ICMPv6";
        extraerIps(packet, out);
    }
}
