package com.juaneuse.sniffx.parser;

import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.Packet;

/**
 *
 * @author juaneuse
 */
public class ArpParser extends PacketParser {

    @Override
    public boolean soporta(Packet packet) {
        return packet.contains(ArpPacket.class);
    }

    @Override
    public void parse(Packet packet, ParsedPacket out) {
        out.protocol = "ARP";
        extraerIps(packet, out);
    }
}

