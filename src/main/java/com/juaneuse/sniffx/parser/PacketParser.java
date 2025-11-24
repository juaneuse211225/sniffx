package com.juaneuse.sniffx.parser;

import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;

/**
 *
 * @author juaneuse
 */
public abstract class PacketParser {

    public abstract boolean soporta(Packet packet);

    public abstract void parse(Packet packet, ParsedPacket out);

    protected void extraerIps(Packet packet, ParsedPacket out) {

        // Si es IPv4
        if (packet.contains(IpV4Packet.class)) {
            IpV4Packet ip4 = packet.get(IpV4Packet.class);
            out.srcIp = ip4.getHeader().getSrcAddr().getHostAddress();
            out.dstIp = ip4.getHeader().getDstAddr().getHostAddress();
            return;
        }

        // Si es IPv6
        if (packet.contains(IpV6Packet.class)) {
            IpV6Packet ip6 = packet.get(IpV6Packet.class);
            out.srcIp = ip6.getHeader().getSrcAddr().getHostAddress();
            out.dstIp =  ip6.getHeader().getDstAddr().getHostAddress();
            return;
        }

        // No es tráfico IP
        out.srcIp = "N/A";
        out.dstIp = "N/A";
    }
}
