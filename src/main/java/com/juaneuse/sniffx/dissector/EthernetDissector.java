package com.juaneuse.sniffx.dissector;

import com.juaneuse.sniffx.model.SniffContext;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;

/**
 *
 * @author juaneuse
 */
public class EthernetDissector implements Dissector {

    @Override
    public boolean supports(Packet packet) {
        return packet.contains(EthernetPacket.class);
    }

    @Override
    public void dissect(Packet packet, SniffContext ctx) {
        EthernetPacket eth = packet.get(EthernetPacket.class);
        if (eth == null) return;
        var h = eth.getHeader();
        ctx.srcMac = h.getSrcAddr().toString();
        ctx.dstMac = h.getDstAddr().toString();
        // guardar etherType si lo necesitas
        ctx.extras.put("etherType", h.getType());
    }
    
}
