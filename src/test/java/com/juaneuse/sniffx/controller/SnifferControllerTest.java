package com.juaneuse.sniffx.controller;

import com.juaneuse.sniffx.model.PacketDetails;
import com.juaneuse.sniffx.model.PacketInfo;
import java.lang.reflect.Field;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import javafx.application.Platform;
import javafx.collections.ObservableList;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.pcap4j.packet.UnknownPacket;

import static org.assertj.core.api.Assertions.assertThat;

class SnifferControllerTest {

    @BeforeAll
    static void initJavaFx() {
        try {
            Platform.startup(() -> {
            });
        } catch (IllegalStateException ignored) {
            // JavaFX ya inicializado en otra prueba
        }
    }

    @Test
    @DisplayName("Cada paquete recibido se inserta una sola vez en la lista lógica")
    void shouldInsertOnlyOneLogicalEntryPerReceivedPacket() throws Exception {
        SnifferController controller = new SnifferController();
        PacketInfo packet = new PacketInfo(UnknownPacket.newPacket(new byte[]{0x01, 0x02}, 0, 2));

        controller.onPacketReceived(packet);
        waitForJavaFxQueue();

        ObservableList<PacketDetails> packetList = packetList(controller);
        assertThat(packetList).hasSize(1);
    }

    @SuppressWarnings("unchecked")
    private ObservableList<PacketDetails> packetList(SnifferController controller) throws Exception {
        Field field = SnifferController.class.getDeclaredField("packetList");
        field.setAccessible(true);
        return (ObservableList<PacketDetails>) field.get(controller);
    }

    private void waitForJavaFxQueue() throws InterruptedException {
        CountDownLatch latch = new CountDownLatch(1);
        Platform.runLater(latch::countDown);
        assertThat(latch.await(2, TimeUnit.SECONDS)).isTrue();
    }
}
