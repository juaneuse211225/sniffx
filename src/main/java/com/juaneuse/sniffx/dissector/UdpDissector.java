package com.juaneuse.sniffx.dissector;

import com.juaneuse.sniffx.model.SniffContext;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UdpPacket;

/**
 *
 * @author juaneuse
 */
public class UdpDissector implements Dissector {
    @Override
    public boolean supports(Packet packet) {
        return packet.contains(UdpPacket.class);
    }

    @Override
    public void dissect(Packet packet, SniffContext ctx) {
        UdpPacket udp = packet.get(UdpPacket.class);
        if (udp == null) return;

        var h = udp.getHeader();
        ctx.protocol = "UDP";
        ctx.srcPort = h.getSrcPort().valueAsInt();
        ctx.dstPort = h.getDstPort().valueAsInt();

        ctx.extras.put("udpLength", h.getLengthAsInt());

        if (udp.getPayload() != null) {
            ctx.extras.put("udpPayloadLength", udp.getPayload().length());
        }
    }
}
