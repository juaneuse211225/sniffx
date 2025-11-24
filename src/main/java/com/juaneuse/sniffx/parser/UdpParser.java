package com.juaneuse.sniffx.parser;

import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UdpPacket;

/**
 *
 * @author juaneuse
 */
public class UdpParser extends PacketParser {

    @Override
    public boolean soporta(Packet packet) {
        return packet.contains(UdpPacket.class);
    }

    @Override
    public void parse(Packet packet, ParsedPacket out) {
        UdpPacket udp = packet.get(UdpPacket.class);
        out.protocol = "UDP";
        out.srcPort = udp.getHeader().getSrcPort().valueAsInt();
        out.dstPort = udp.getHeader().getDstPort().valueAsInt();
        extraerIps(packet, out);
    }
    
    
}
