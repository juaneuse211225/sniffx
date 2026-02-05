package com.juaneuse.sniffx.dissector;

import com.juaneuse.sniffx.model.SniffContext;
import org.pcap4j.packet.Packet;

/**
 *
 * @author juaneuse
 */
public interface Dissector {
    /** 
     * Decide si este dissector puede procesar el paquete 
     * (p. ej. packet.contains(IpV4Packet.class)) 
     **/
    boolean supports(Packet packet);

    /** Llena/actualiza el SniffContext con la info extraída */
    void dissect(Packet packet, SniffContext ctx);
}
