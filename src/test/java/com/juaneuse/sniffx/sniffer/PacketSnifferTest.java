package com.juaneuse.sniffx.sniffer;

import com.juaneuse.sniffx.model.PacketInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.*;
import org.mockito.junit.jupiter.MockitoExtension;
import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.util.List;
import static org.assertj.core.api.Assertions.assertThat;
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
    @SuppressWarnings("unused")
    void setup() throws Exception {
        sniffer = new PacketSniffer();

        // inyectar manualmente mockHandle dentro de sniffer usando reflexión
        Field field = PacketSniffer.class.getDeclaredField("handle");
        field.setAccessible(true);
        field.set(sniffer, mockHandle);
    }

    // -----------------------------
    //   OBSERVER MANAGEMENT TESTS
    // -----------------------------
    @Test
    void testAddObserver() {
        sniffer.addObserver(mockObserver);
        sniffer.addObserver(mockObserver); // no debe duplicar

        Field field;
        try {
            field = PacketSniffer.class.getDeclaredField("packetObservers");
            field.setAccessible(true);
            List<?> observers = (List<?>) field.get(sniffer);

            assertThat(observers).hasSize(1);
        } catch (IllegalAccessException | IllegalArgumentException | NoSuchFieldException | SecurityException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void testRemoveObserver() {
        sniffer.addObserver(mockObserver);
        sniffer.removeObserver(mockObserver);

        Field field;
        try {
            field = PacketSniffer.class.getDeclaredField("packetObservers");
            field.setAccessible(true);
            List<?> observers = (List<?>) field.get(sniffer);

            assertThat(observers).isEmpty();
        } catch (IllegalAccessException | IllegalArgumentException | NoSuchFieldException | SecurityException e) {
            throw new RuntimeException(e);
        }
    }

    // -----------------------------
    //   NOTIFICATION TESTS
    // -----------------------------
    @Test
    void testNotifyObservers_singlePacket() {
        sniffer.addObserver(mockObserver);

        when(mockPacket.getRawData()).thenReturn(new byte[]{0x01, 0x02, 0x03});
        PacketInfo info = new PacketInfo(mockPacket);

        snifferTestNotify(sniffer, info);

        verify(mockObserver, times(1)).onPacketReceived(info);
    }

    @Test
    void testNotifyObservers_errorInOneObserverDoesNotStopOthers() {
        PacketObserver faulty = mock(PacketObserver.class);
        doThrow(new RuntimeException("Error intencional")).when(faulty).onPacketReceived(any());

        PacketObserver working = mock(PacketObserver.class);

        sniffer.addObserver(faulty);
        sniffer.addObserver(working);

        when(mockPacket.getRawData()).thenReturn(new byte[]{0x01, 0x02, 0x03});
        PacketInfo info = new PacketInfo(mockPacket);

        snifferTestNotify(sniffer, info);

        verify(working, times(1)).onPacketReceived(info);
    }

    private void snifferTestNotify(PacketSniffer sniffer, PacketInfo info) {
        try {
            var notifyMethod = PacketSniffer.class.getDeclaredMethod("notifyObservers", PacketInfo.class);
            notifyMethod.setAccessible(true);
            notifyMethod.invoke(sniffer, info);

        } catch (IllegalAccessException | NoSuchMethodException | SecurityException | InvocationTargetException e) {
            throw new RuntimeException(e);
        }
    }

    // -----------------------------
    //   STOP TESTS
    // -----------------------------
    @Test
    void testStopCallsBreakLoop() throws Exception {
        when(mockHandle.isOpen()).thenReturn(true);

        sniffer.stop();

        verify(mockHandle, times(1)).breakLoop();
    }

    @Test
    void testStopWhenHandleClosedDoesNotCallBreakLoop() throws Exception {
        when(mockHandle.isOpen()).thenReturn(false);

        sniffer.stop();

        verify(mockHandle, never()).breakLoop();
    }

    // -----------------------------
    //   START TESTS (SPY LOOP)
    // -----------------------------
    @Test
    void testStartCannotStartTwice() throws Exception {
        Field runningField = PacketSniffer.class.getDeclaredField("running");
        runningField.setAccessible(true);

        runningField.set(sniffer, true); // simular que ya está corriendo

        sniffer.start("eth0", List.of(mockInterface), "");

        // como ya estaba corriendo NO debe intentar abrir handle ni loop
        verify(mockHandle, never()).loop(anyInt(), any(PacketListener.class));
    }

    @Test
    void testStartTriggersLoopAndObserverReceivesPacket() throws Exception {

        when(mockInterface.getName()).thenReturn("eth0");
        when(mockInterface.openLive(
                anyInt(),
                any(PcapNetworkInterface.PromiscuousMode.class),
                anyInt()))
                .thenReturn(mockHandle);

        when(mockPacket.getRawData())
                .thenReturn(new byte[]{0x01, 0x02, 0x03});

        List<PcapNetworkInterface> list = List.of(mockInterface);

        doAnswer(invocation -> {
            PacketListener listener = invocation.getArgument(1);
            listener.gotPacket(mockPacket); // simular llegada de paquete
            return null;
        }).when(mockHandle).loop(anyInt(), any(PacketListener.class));

        sniffer.addObserver(mockObserver);

        sniffer.start("eth0", list, "");

        Thread.sleep(50); // darle tiempo al hilo virtual

        verify(mockObserver, atLeastOnce()).onPacketReceived(any(PacketInfo.class));
    }

}
