package com.juaneuse.sniffx.controller;

import com.juaneuse.sniffx.runtime.SnifferRuntimeContext;
import com.juaneuse.sniffx.runtime.SnifferStateObserver;
import com.juaneuse.sniffx.runtime.SnifferConfig;
import com.juaneuse.sniffx.sniffer.PacketObserver;
import com.juaneuse.sniffx.sniffer.PacketSniffer;
import java.util.Collections;
import java.util.List;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;

/**
 *
 * @author juaneuse
 */
public class SniffingService {

    private final PacketSniffer sniffer;
    private final SnifferRuntimeContext runtimeContext;

    public SniffingService() {
        this.sniffer = new PacketSniffer();
        // El RuntimeContext es el "cerebro" que maneja los estados
        this.runtimeContext = new SnifferRuntimeContext(sniffer);
    }

    public void addPacketObserver(PacketObserver observer) {
        sniffer.addObserver(observer);
    }

    public void addStateObserver(SnifferStateObserver observer) {
        runtimeContext.addObserver(observer);
    }

    public List<String> getInterfaceNames() {
        try {
            return sniffer.listInterfaces().stream()
                    .map(PcapNetworkInterface::getName)
                    .toList();
        } catch (PcapNativeException ex) {
            return Collections.emptyList();
        }
    }

    public void startCapture(String interfaceName, String bpfFilter) {
        try {
            var interfaces = sniffer.listInterfaces();
            // Primero configuramos el contexto
            SnifferConfig config = new SnifferConfig(interfaceName, interfaces, bpfFilter);
            runtimeContext.configure(config);

            // El contexto decide si puede iniciar según su estado actual
            runtimeContext.start();
        } catch (PcapNativeException ex) {
            System.getLogger(SniffingService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }
    }

    public void stopCapture() {
        runtimeContext.stop();
    }

    public String getCurrentStateName() {
        return runtimeContext.getStateName();
    }
}
