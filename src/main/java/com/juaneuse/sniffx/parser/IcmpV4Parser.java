package com.juaneuse.sniffx.parser;

import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.Packet;

/**
 *
 * @author juaneuse
 */
public class IcmpV4Parser extends PacketParser {

    @Override
    public boolean soporta(Packet packet) {
        return packet.contains(IcmpV4CommonPacket.class);
    }

    @Override
    public void parse(Packet packet, ParsedPacket out) {
        out.protocol = "ICMPv4";
        extraerIps(packet, out);
    }
}

