package com.juaneuse.sniffx.sniffer;

import com.juaneuse.sniffx.model.PacketInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.*;
import org.mockito.junit.jupiter.MockitoExtension;
import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 *
 * @author juaneuse
 */
@ExtendWith(MockitoExtension.class)
class PacketSnifferTest {

    @Mock
    private PcapNetworkInterface mockInterface;
    @Mock
    private PcapHandle mockHandle;
    @Mock
    private Packet mockPacket;
    @Mock
    private PacketObserver mockObserver;

    private PacketSniffer sniffer;

    @BeforeEach
    void setup() {
        // CLEAN: Ya no hay reflexión. Inyectamos el mock directamente.
        // Cada vez que el sniffer necesite un handle, usará nuestro mock.
        sniffer = new PacketSniffer(nif -> mockHandle);
    }

    @Test
    @DisplayName("Debe iniciar captura, aplicar filtro y notificar paquetes")
    void testStartFlow() throws Exception {
        // GIVEN
        String interfaceName = "eth0";
        String filter = "tcp";
        when(mockInterface.getName()).thenReturn(interfaceName);

        // Simulamos que al ejecutar loop, el listener recibe un paquete inmediatamente
        doAnswer(invocation -> {
            PacketListener listener = invocation.getArgument(1);
            listener.gotPacket(mockPacket);
            return null;
        }).when(mockHandle).loop(anyInt(), any(PacketListener.class));

        sniffer.addObserver(mockObserver);

        // WHEN
        sniffer.start(interfaceName, List.of(mockInterface), filter);

        // THEN
        // Verificamos configuración del handle
        verify(mockHandle).setFilter(eq(filter), any());

        // Verificamos notificación asíncrona con timeout (porque es un Virtual Thread)
        verify(mockObserver, timeout(200)).onPacketReceived(any(PacketInfo.class));
    }

    @Test
    @DisplayName("Debe lanzar excepción si la interfaz no está en la lista")
    void testStartInterfaceNotFound() {
        assertThatThrownBy(()
                -> sniffer.start("wlan0", List.of(mockInterface), "")
        ).isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Fallo al abrir el canal de captura");
    }

    @Test
    @DisplayName("Debe cerrar recursos correctamente al detener")
    void testStopResources() throws Exception {
        // GIVEN: Necesitamos que el handle esté asignado internamente
        when(mockInterface.getName()).thenReturn("eth0");
        sniffer.start("eth0", List.of(mockInterface), "");
        when(mockHandle.isOpen()).thenReturn(true);

        // WHEN
        sniffer.stop();

        // THEN
        verify(mockHandle).breakLoop();
        verify(mockHandle).close();
    }

    @Test
    @DisplayName("Un observer con error no debe impedir que otros reciban el paquete")
    void testObserverResilience() throws Exception {
        // GIVEN
        PacketObserver faultyObserver = mock(PacketObserver.class);
        doThrow(new RuntimeException("Boom!")).when(faultyObserver).onPacketReceived(any());

        sniffer.addObserver(faultyObserver);
        sniffer.addObserver(mockObserver);

        // Simulamos el flujo de llegada de paquete
        when(mockInterface.getName()).thenReturn("eth0");
        doAnswer(inv -> {
            PacketListener l = inv.getArgument(1);
            l.gotPacket(mockPacket);
            return null;
        }).when(mockHandle).loop(anyInt(), any(PacketListener.class));

        // WHEN
        sniffer.start("eth0", List.of(mockInterface), "");

        // THEN
        // El observer sano debe recibirlo aunque el otro haya explotado
        verify(mockObserver, timeout(200)).onPacketReceived(any());
        verify(faultyObserver).onPacketReceived(any());
    }

    @Test
    @DisplayName("No debe añadir el mismo observer dos veces")
    void testNoDuplicateObservers() throws Exception {
        // Como no podemos ver la lista privada, probamos el comportamiento:
        // Si lo añado dos veces, ¿recibe dos notificaciones? No debería.
        sniffer.addObserver(mockObserver);
        sniffer.addObserver(mockObserver);

        // Simular llegada de 1 paquete
        when(mockInterface.getName()).thenReturn("eth0");
        doAnswer(inv -> {
            ((PacketListener) inv.getArgument(1)).gotPacket(mockPacket);
            return null;
        }).when(mockHandle).loop(anyInt(), any(PacketListener.class));

        sniffer.start("eth0", List.of(mockInterface), "");

        // Verificamos que SOLO se llamó 1 vez
        verify(mockObserver, timeout(200).times(1)).onPacketReceived(any());
    }

    @Test
    void testBadFilterThrowsException() throws Exception {
        when(mockInterface.getName()).thenReturn("eth0");
        // Simulamos que el filtro es inválido
        doThrow(PcapNativeException.class).when(mockHandle).setFilter(anyString(), any());

        assertThatThrownBy(()
                -> sniffer.start("eth0", List.of(mockInterface), "filtro_basura")
        ).isInstanceOf(RuntimeException.class);
    }
}
