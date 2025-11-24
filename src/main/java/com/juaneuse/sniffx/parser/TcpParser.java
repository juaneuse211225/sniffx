package com.juaneuse.sniffx.parser;

import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

/**
 *
 * @author juaneuse
 */
public class TcpParser extends PacketParser {

    @Override
    public boolean soporta(Packet packet) {
        return packet.contains(TcpPacket.class);
    }

    @Override
    public void parse(Packet packet, ParsedPacket out) {
        TcpPacket tcp = packet.get(TcpPacket.class);
        TcpPacket.TcpHeader h = tcp.getHeader();

        out.protocol = "TCP";
        out.srcPort = h.getSrcPort().valueAsInt();
        out.dstPort = h.getDstPort().valueAsInt();

        StringBuilder sb = new StringBuilder();
        if (h.getUrg()) sb.append("URG ");
        if (h.getAck()) sb.append("ACK ");
        if (h.getPsh()) sb.append("PSH ");
        if (h.getRst()) sb.append("RST ");
        if (h.getSyn()) sb.append("SYN ");
        if (h.getFin()) sb.append("FIN ");

        out.tcpFlags = sb.toString().trim();
        
        extraerIps(packet, out);
    }
}
