package com.juaneuse.sniffx.parser;

import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;

/**
 *
 * @author juaneuse
 */
public class Ipv6Parser extends PacketParser {

    @Override
    public boolean soporta(Packet packet) {
        return packet.contains(IpV6Packet.class);
    }

    @Override
    public void parse(Packet packet, ParsedPacket out) {
        IpV6Packet ip = packet.get(IpV6Packet.class);

        out.ipVersion = "IPv6";
        out.srcIp = ip.getHeader().getSrcAddr().getHostAddress();
        out.dstIp = ip.getHeader().getDstAddr().getHostAddress();
    }
}
