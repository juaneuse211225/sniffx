package com.juaneuse.sniffx.controller;

import com.juaneuse.sniffx.runtime.SnifferConfig;
import com.juaneuse.sniffx.runtime.SnifferRuntimeContext;
import com.juaneuse.sniffx.sniffer.PacketSniffer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.*;
/**
 *
 * @author juaneuse
 */
@ExtendWith(MockitoExtension.class)
class SniffingServiceTest {

    @Mock
    private PacketSniffer mockSniffer;

    @Mock
    private SnifferRuntimeContext mockContext;

    @Mock
    private PcapNetworkInterface mockNetworkInterface;

    private SniffingService service;

    @BeforeEach
    void setup() {
        // Inyectamos los mocks usando el nuevo constructor
        service = new SniffingService(mockSniffer, mockContext);
    }

    @Test
    @DisplayName("Debe devolver nombres de interfaces correctamente")
    void shouldReturnInterfaceNames() throws PcapNativeException {
        // GIVEN
        String interfaceName = "eth0";
        when(mockNetworkInterface.getName()).thenReturn(interfaceName);
        given(mockSniffer.listInterfaces()).willReturn(List.of(mockNetworkInterface));

        // WHEN
        List<String> names = service.getInterfaceNames();

        // THEN
        assertThat(names).containsExactly(interfaceName);
    }

    @Test
    @DisplayName("Debe devolver lista vacía si hay error al listar interfaces")
    void shouldReturnEmptyListOnException() throws PcapNativeException {
        // GIVEN
        given(mockSniffer.listInterfaces()).willThrow(new PcapNativeException("Error nativo"));

        // WHEN
        List<String> names = service.getInterfaceNames();

        // THEN
        assertThat(names).isEmpty();
    }

    @Test
    @DisplayName("Debe configurar y arrancar el contexto al iniciar captura")
    void shouldConfigureAndStartContext() throws PcapNativeException {
        // GIVEN
        String targetInterface = "wlan0";
        String filter = "tcp port 80";
        
        // --- CORRECCIÓN AQUÍ ---
        // Eliminamos la línea: when(mockNetworkInterface.getName())... 
        // porque SniffingService NO valida el nombre, solo pasa la lista al contexto.
        
        // Solo definimos que el sniffer devuelva la lista con nuestra interfaz mockeada
        given(mockSniffer.listInterfaces()).willReturn(List.of(mockNetworkInterface));

        // WHEN
        service.startCapture(targetInterface, filter);

        // THEN
        // 1. Verificamos que se configuró el contexto con los datos correctos
        ArgumentCaptor<SnifferConfig> configCaptor = ArgumentCaptor.forClass(SnifferConfig.class);
        verify(mockContext).configure(configCaptor.capture());

        SnifferConfig capturedConfig = configCaptor.getValue();
        assertThat(capturedConfig.interfaceName()).isEqualTo(targetInterface);
        assertThat(capturedConfig.bpfFilter()).isEqualTo(filter);
        
        // Verificamos que la lista dentro de config contiene nuestro mock (sin importar su nombre)
        assertThat(capturedConfig.interfaces()).contains(mockNetworkInterface);

        // 2. Verificamos que se dio la orden de arranque
        verify(mockContext).start();
    }

    @Test
    @DisplayName("No debe arrancar si falla la obtención de interfaces")
    void shouldNotStartIfInterfacesFail() throws PcapNativeException {
        // GIVEN
        given(mockSniffer.listInterfaces()).willThrow(new PcapNativeException("Fallo crítico"));

        // WHEN
        service.startCapture("eth0", "");

        // THEN
        verify(mockContext, never()).configure(any());
        verify(mockContext, never()).start();
    }

    @Test
    @DisplayName("Debe detener el contexto al llamar a stopCapture")
    void shouldStopContext() {
        // WHEN
        service.stopCapture();

        // THEN
        verify(mockContext).stop();
    }
}
