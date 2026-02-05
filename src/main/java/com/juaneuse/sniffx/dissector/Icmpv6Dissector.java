package com.juaneuse.sniffx.dissector;

import com.juaneuse.sniffx.model.SniffContext;
import org.pcap4j.packet.IcmpV6CommonPacket;
import org.pcap4j.packet.Packet;

/**
 *
 * @author juaneuse
 */
public class Icmpv6Dissector implements Dissector {

    @Override
    public boolean supports(Packet packet) {
        return packet.contains(IcmpV6CommonPacket.class);
    }

    @Override
    public void dissect(Packet packet, SniffContext ctx) {
        IcmpV6CommonPacket icmp = packet.get(IcmpV6CommonPacket.class);
        if (icmp == null) return;

        var h = icmp.getHeader();
        ctx.protocol = "ICMPv6";
        ctx.extras.put("icmpType", h.getType().value());
        ctx.extras.put("icmpCode", h.getCode().value());

        if (icmp.getPayload() != null) {
            ctx.extras.put("icmpPayloadLength", icmp.getPayload().length());
        }
    }
    
}
