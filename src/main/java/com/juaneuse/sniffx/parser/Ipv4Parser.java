package com.juaneuse.sniffx.parser;

import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;

/**
 *
 * @author juaneuse
 */
public class Ipv4Parser extends PacketParser {

    @Override
    public boolean soporta(Packet packet) {
        return packet.contains(IpV4Packet.class);
    }

    @Override
    public void parse(Packet packet, ParsedPacket out) {
        IpV4Packet ip = packet.get(IpV4Packet.class);

        out.ipVersion = "IPv4";
        out.srcIp = ip.getHeader().getSrcAddr().getHostAddress();
        out.dstIp = ip.getHeader().getDstAddr().getHostAddress();
    }
}

