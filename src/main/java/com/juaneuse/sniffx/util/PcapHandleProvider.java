package com.juaneuse.sniffx.util;

import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;

/**
 *
 * @author juaneuse
 */
@FunctionalInterface
public interface PcapHandleProvider {
    /**
     * Define CÓMO se abre el canal de captura.
     * @param nif La interfaz de red seleccionada.
     * @return Un handle abierto y listo para usar.
     */
    PcapHandle open(PcapNetworkInterface nif) throws PcapNativeException;
}
