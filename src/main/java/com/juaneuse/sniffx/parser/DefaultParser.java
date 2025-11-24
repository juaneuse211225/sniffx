package com.juaneuse.sniffx.parser;

import org.pcap4j.packet.Packet;

/**
 *
 * @author juaneuse
 */
public class DefaultParser extends PacketParser {

    @Override
    public boolean soporta(Packet packet) {
        return true;
    }

    @Override
    public void parse(Packet packet, ParsedPacket out) {
        out.protocol = "Desconocido";
        extraerIps(packet, out);
    }
}
