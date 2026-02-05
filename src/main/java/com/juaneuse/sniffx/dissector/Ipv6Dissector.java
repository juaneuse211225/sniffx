package com.juaneuse.sniffx.dissector;

import com.juaneuse.sniffx.model.SniffContext;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;

/**
 *
 * @author juaneuse
 */
public class Ipv6Dissector implements Dissector {

    @Override
    public boolean supports(Packet packet) {
        return packet.contains(IpV6Packet.class);
    }

    @Override
    public void dissect(Packet packet, SniffContext ctx) {
        IpV6Packet ip = packet.get(IpV6Packet.class);
        if (ip == null) return;
        var h = ip.getHeader();
        ctx.ipVersion = "IPv6";
        ctx.srcIp = h.getSrcAddr().getHostAddress();
        ctx.dstIp = h.getDstAddr().getHostAddress();
        ctx.extras.put("hopLimit", h.getHopLimitAsInt());
        ctx.extras.put("ipProtocol", h.getNextHeader());
    }
    
}
