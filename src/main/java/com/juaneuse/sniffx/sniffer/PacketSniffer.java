package com.juaneuse.sniffx.sniffer;

import com.juaneuse.sniffx.model.PacketInfo;
import java.util.ArrayList;
import java.util.List;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;

/**
 *
 * @author juaneuse
 */

public class PacketSniffer {

    private List<PacketObserver> packetObservers = new ArrayList<>();
    private boolean running;
    private PcapHandle handle;

    public PacketSniffer(List<PacketObserver> packetObservers, boolean running, PcapHandle handle) {
        this.packetObservers = packetObservers;
        this.running = running;
        this.handle = handle;
    }

    public PacketSniffer() {

    }

    public void addObserver(PacketObserver o) {
        packetObservers.add(o);
    }

    public void removeObserver(PacketObserver o) {
        packetObservers.remove(o);
    }

    public List<PcapNetworkInterface> listInterfaces() throws PcapNativeException {
        try {
            List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();
            if (interfaces == null || interfaces.isEmpty()) {
                System.out.println("No se encontraron interfaces de red.");
            }
            return interfaces;
        } catch (PcapNativeException e) {
            System.out.println("Error al obtener interfaces de red: " + e.getMessage());
            throw e;
        }
    }

    public void start(String interfaceName, List<PcapNetworkInterface> listInterfaces) throws PcapNativeException {
        PcapNetworkInterface nif = listInterfaces.stream()
                .filter(i -> i.getName().equals(interfaceName))
                .findFirst()
                .orElseThrow(() -> new PcapNativeException("Interfaz no encontrada"));

        int snaplen = 65536;
        PromiscuousMode mode = PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;
        int timeout = 10;

        handle = nif.openLive(snaplen, mode, timeout);
        running = true;

        Thread.startVirtualThread(() -> {
            while (running) {
                try {
                    Packet packet = handle.getNextPacket();
                    if (packet != null) {
                        notifyObservers(new PacketInfo(packet));
                    } else {
                        Thread.sleep(10); // evita busy loop
                    }
                } catch (NotOpenException e) {
                    System.out.println("Handle cerrado inesperadamente " + e.getMessage());
                    running = false;
                } catch (Exception e) {
                    System.out.println("Error capturando paquete " + e.getMessage());
                }
            }
            if (handle != null && handle.isOpen()) {
                handle.close();
            }
        });

    }

    public void stop() throws NotOpenException {
        running = false;
        if (handle != null && handle.isOpen()) {
            handle.breakLoop();
            System.out.println("Hilo virtual detenido");
        }
    }

    private void notifyObservers(PacketInfo p) {
        for (PacketObserver o : packetObservers) {
            o.onPacketReceived(p);
        }
    }
}
