package com.juaneuse.sniffx.sniffer;

import com.juaneuse.sniffx.model.PacketInfo;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author juaneuse
 */
public class PacketSniffer {

    private static final Logger logger = LoggerFactory.getLogger(PacketSniffer.class);

    private CopyOnWriteArrayList<PacketObserver> packetObservers = new CopyOnWriteArrayList<>();
    private volatile boolean running;
    private PcapHandle handle;

    public PacketSniffer() {
    }

    public void addObserver(PacketObserver o) {
        packetObservers.addIfAbsent(o);
    }

    public void removeObserver(PacketObserver o) {
        packetObservers.remove(o);
    }

    public List<PcapNetworkInterface> listInterfaces() throws PcapNativeException {
        List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();
        if (interfaces == null || interfaces.isEmpty()) {
            logger.warn("No se encontraron interfaces de red.");
        }
        return interfaces;
    }

    public synchronized void start(String interfaceName, List<PcapNetworkInterface> listInterfaces) throws PcapNativeException {

        if (running) {
            logger.warn("La captura ya esta en ejecucion");
            return;
        }

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
            logger.info("Iniciando captura...");

            try {
                handle.loop(-1, new PacketListener() {
                    @Override
                    public void gotPacket(Packet packet) {
                        if (!running) {
                            return;
                        }
                        notifyObservers(new PacketInfo(packet));
                    }
                });

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                logger.info("Hilo de captura interrumpido");
            } catch (NotOpenException e) {
                logger.error("Handle cerrado inesperadamente: {}", e.getMessage());
            } catch (Exception e) {
                logger.error("Error capturando paquete: {}", e.getMessage(), e);
            } finally {
                if (handle != null && handle.isOpen()) {
                    handle.close();
                }
                running = false;
                logger.info("Hilo de captura finalizado.");
            }
        });

    }

    public synchronized void stop() throws NotOpenException {
        running = false;
        if (handle != null && handle.isOpen()) {
            try {
                handle.breakLoop();
                logger.info("Solicitado stop: breakLoop enviado.");
            } catch (NotOpenException e) {
                logger.warn("Intento de breakLoop sobre handle no abierto.");
            }
        }
    }

    private void notifyObservers(PacketInfo p) {
        for (PacketObserver o : packetObservers) {
            try {
                o.onPacketReceived(p);
            } catch (Exception e) {
                logger.error("Error notificando observer: {}", e.getMessage(), e);
            }
        }
    }
}
