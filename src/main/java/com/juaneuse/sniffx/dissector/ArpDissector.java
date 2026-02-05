package com.juaneuse.sniffx.dissector;

import com.juaneuse.sniffx.model.SniffContext;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.Packet;

/**
 *
 * @author juaneuse
 */
public class ArpDissector implements Dissector {
    @Override
    public boolean supports(Packet packet) {
        return packet.contains(ArpPacket.class);
    }

    @Override
    public void dissect(Packet packet, SniffContext ctx) {
        ArpPacket arp = packet.get(ArpPacket.class);
        if (arp == null) return;

        var h = arp.getHeader();
        ctx.protocol = "ARP";
        ctx.srcIp = h.getSrcProtocolAddr().getHostAddress();
        ctx.dstIp = h.getDstProtocolAddr().getHostAddress();
        ctx.extras.put("arpOp", h.getOperation().name());
        ctx.extras.put("arpSha", h.getSrcHardwareAddr().toString());
        ctx.extras.put("arpTha", h.getDstHardwareAddr().toString());
    }
}
