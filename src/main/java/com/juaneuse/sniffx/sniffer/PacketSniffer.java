package com.juaneuse.sniffx.sniffer;

import com.juaneuse.sniffx.model.PacketInfo;
import com.juaneuse.sniffx.util.PcapHandleProvider;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import org.pcap4j.core.BpfProgram;
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

    private final CopyOnWriteArrayList<PacketObserver> packetObservers = new CopyOnWriteArrayList<>();
    private PcapHandle handle;
    private final PcapHandleProvider handleProvider;

    public PacketSniffer() {
        this((nif) -> nif.openLive(65536, PromiscuousMode.PROMISCUOUS, 10));
    }

    // para test unitarios
    public PacketSniffer(PcapHandleProvider provider) {
        this.handleProvider = provider;
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

    public synchronized void start(
        String interfaceName,
        List<PcapNetworkInterface> listInterfaces,
        String bpfFilter
) {
    // 1. Limpieza del filtro
    if (bpfFilter != null && bpfFilter.isBlank()) {
        bpfFilter = null;
    }

    try {
        PcapNetworkInterface nif = listInterfaces.stream()
                .filter(i -> interfaceName.equals(i.getName()))
                .findFirst()
                .orElseThrow(() -> new PcapNativeException("Interfaz no encontrada"));

        handle = handleProvider.open(nif);

        if (bpfFilter != null) {
            handle.setFilter(bpfFilter, BpfProgram.BpfCompileMode.OPTIMIZE);
            logger.info("Filtro BPF aplicado: {}", bpfFilter);
        }

        Thread.startVirtualThread(() -> {
            logger.info("Iniciando captura en hilo virtual...");
            try {
                handle.loop(-1, new PacketListener() {
                    @Override
                    public void gotPacket(Packet packet) {
                        notifyObservers(new PacketInfo(packet));
                    }
                });
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                logger.info("Hilo de captura interrumpido.");
            } catch (NotOpenException | PcapNativeException e) {
                logger.error("Error crítico durante el loop de captura", e);
                // Aquí podrías notificar a un ErrorObserver si lo tuvieras
            } finally {
                logger.info("Hilo de captura finalizado.");
            }
        });

    } catch (NotOpenException | PcapNativeException e) {
        logger.error("No se pudo iniciar la captura: {}", e.getMessage());
        throw new RuntimeException("Fallo al abrir el canal de captura", e);
    }
}

    public synchronized void stop() {
        try {
            if (handle != null && handle.isOpen()) {
                handle.breakLoop();
                logger.info("Solicitado stop: breakLoop enviado.");

                handle.close();
                logger.info("Handle cerrado por STOP.");
            }
        } catch (NotOpenException e) {
            throw new RuntimeException("Error deteniendo captura", e);
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
