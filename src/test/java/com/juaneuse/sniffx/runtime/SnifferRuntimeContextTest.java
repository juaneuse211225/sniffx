package com.juaneuse.sniffx.runtime;

import com.juaneuse.sniffx.sniffer.PacketSniffer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.pcap4j.core.PcapNetworkInterface;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SnifferRuntimeContextTest {

    @Mock private PacketSniffer mockSniffer;
    @Mock private SnifferStateObserver mockObserver;
    // No necesitamos mockNif si no vamos a validar su comportamiento interno aquí
    @Mock private PcapNetworkInterface mockNif; 

    private SnifferRuntimeContext context;

    @BeforeEach
    void setup() {
        context = new SnifferRuntimeContext(mockSniffer);
        context.addObserver(mockObserver);
    }

    @Test
    @DisplayName("Debe iniciar en estado STOPPED")
    void shouldStartInStoppedState() {
        assertThat(context.getStateName()).isEqualTo("STOPPED");
    }

    @Test
    @DisplayName("Debe pasar a RUNNING cuando se inicia correctamente")
    void shouldTransitionToRunning() {
        // GIVEN: Creamos una configuración válida. 
        // No necesitamos configurar getName() porque el context no lo usa directamente.
        SnifferConfig config = new SnifferConfig("eth0", List.of(mockNif), "tcp");
        context.configure(config);

        // WHEN
        context.start();

        // THEN
        assertThat(context.getStateName()).isEqualTo("RUNNING");
        verify(mockObserver).onStateChanged(any(RunningState.class));
    }

    @Test
    @DisplayName("Debe pasar a ERROR si el sniffer falla al arrancar")
    void shouldTransitionToErrorOnFailure() {
        // GIVEN
        SnifferConfig config = new SnifferConfig("eth0", List.of(mockNif), "tcp");
        context.configure(config);
        
        // Aquí sí definimos un comportamiento que SE USA: el fallo del sniffer
        doThrow(new RuntimeException("Fallo crítico")).when(mockSniffer)
                .start(anyString(), anyList(), anyString());

        // WHEN
        context.start();

        // THEN
        assertThat(context.getStateName()).isEqualTo("ERROR");
        verify(mockObserver).onStateChanged(any(ErrorState.class));
    }

    @Test
    @DisplayName("No debe notificar si el estado es el mismo")
    void shouldNotNotifyIfStateIsSame() {
        // GIVEN
        SnifferConfig config = new SnifferConfig("eth0", List.of(mockNif), "tcp");
        context.configure(config);
        
        context.start(); // Primera vez: cambia de STOPPED a RUNNING
        reset(mockObserver); // Limpiamos para verificar que no haya segunda notificación

        // WHEN
        context.start(); // Segunda vez: ya está en RUNNING

        // THEN
        verify(mockObserver, never()).onStateChanged(any());
    }
}