package com.juaneuse.sniffx.dissector;

import com.juaneuse.sniffx.model.SniffContext;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.IpNumber;

/**
 *
 * @author juaneuse
 */
public class Ipv4Dissector implements Dissector {

    @Override
    public boolean supports(Packet packet) {
        return packet.contains(IpV4Packet.class);
    }

    @Override
    public void dissect(Packet packet, SniffContext ctx) {
        IpV4Packet ip = packet.get(IpV4Packet.class);
        if (ip == null) return;
        var h = ip.getHeader();
        ctx.ipVersion = "IPv4";
        ctx.srcIp = h.getSrcAddr().getHostAddress();
        ctx.dstIp = h.getDstAddr().getHostAddress();
        ctx.extras.put("ttl", h.getTtlAsInt());
        ctx.extras.put("ipProtocol", h.getProtocol());
    }
    
}
