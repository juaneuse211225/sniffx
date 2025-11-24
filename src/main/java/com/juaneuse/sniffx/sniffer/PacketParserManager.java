package com.juaneuse.sniffx.sniffer;

import com.juaneuse.sniffx.parser.*;
import org.pcap4j.packet.Packet;

import java.util.List;

/**
 *
 * @author juaneuse
 */
public class PacketParserManager {

    private static final List<PacketParser> PARSERS = List.of(
            new TcpParser(),
            new UdpParser(),
            new IcmpV4Parser(),
            new IcmpV6Parser(),
            new ArpParser(),
            new Ipv4Parser(),
            new Ipv6Parser(),
            new DefaultParser()
    );

    public static ParsedPacket parse(Packet packet, int length) {
        ParsedPacket out = new ParsedPacket();
        out.length = length;

        PARSERS.stream()
                .filter(p -> p.soporta(packet))
                .findFirst()
                .orElse(new DefaultParser())
                .parse(packet, out);

        return out;
    }
}

