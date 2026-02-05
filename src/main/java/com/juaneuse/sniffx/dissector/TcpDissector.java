package com.juaneuse.sniffx.dissector;

import com.juaneuse.sniffx.model.SniffContext;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

/**
 *
 * @author juaneuse
 */
public class TcpDissector implements Dissector {
    @Override
    public boolean supports(Packet packet) {
        return packet.contains(TcpPacket.class);
    }

    @Override
    public void dissect(Packet packet, SniffContext ctx) {
        TcpPacket tcp = packet.get(TcpPacket.class);
        if (tcp == null) return;

        var h = tcp.getHeader();
        ctx.protocol = "TCP";
        ctx.srcPort = h.getSrcPort().valueAsInt();
        ctx.dstPort = h.getDstPort().valueAsInt();

        // Flags
        ctx.extras.put("tcpFlags", buildFlags(h));
        ctx.extras.put("seq", h.getSequenceNumber());
        ctx.extras.put("ack", h.getAcknowledgmentNumber());
        ctx.extras.put("window", h.getWindowAsInt());

        if (tcp.getPayload() != null) {
            ctx.extras.put("tcpPayloadLength", tcp.getPayload().length());
        }
    }
    
    private String buildFlags(TcpPacket.TcpHeader h) {
    StringBuilder sb = new StringBuilder();

    if (h.getSyn()) sb.append("SYN ");
    if (h.getAck()) sb.append("ACK ");
    if (h.getFin()) sb.append("FIN ");
    if (h.getRst()) sb.append("RST ");
    if (h.getPsh()) sb.append("PSH ");
    if (h.getUrg()) sb.append("URG ");

    return sb.toString().trim();
}
}
