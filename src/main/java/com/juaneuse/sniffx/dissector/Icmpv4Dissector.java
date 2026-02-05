package com.juaneuse.sniffx.dissector;

import com.juaneuse.sniffx.model.SniffContext;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.Packet;

/**
 *
 * @author juaneuse
 */
public class Icmpv4Dissector implements Dissector {

    @Override
    public boolean supports(Packet packet) {
        return packet.contains(IcmpV4CommonPacket.class);
    }

    @Override
    public void dissect(Packet packet, SniffContext ctx) {
        IcmpV4CommonPacket icmp = packet.get(IcmpV4CommonPacket.class);
        if (icmp == null) return;

        var h = icmp.getHeader();
        ctx.protocol = "ICMPv4";
        ctx.extras.put("icmpType", h.getType().value());
        ctx.extras.put("icmpCode", h.getCode().value());

        if (icmp.getPayload() != null) {
            ctx.extras.put("icmpPayloadLength", icmp.getPayload().length());
        }
    }
    
}
