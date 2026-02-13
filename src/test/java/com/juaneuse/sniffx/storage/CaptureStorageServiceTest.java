package com.juaneuse.sniffx.storage;

import com.juaneuse.sniffx.model.PacketDetails;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class CaptureStorageServiceTest {

    @TempDir
    Path tempDir;

    @Test
    void shouldAppendAndReadPage() throws IOException {
        CaptureStorageService storage = new CaptureStorageService(tempDir);
        storage.startSession("eth0", "tcp");

        storage.append(packetAt(1));
        storage.append(packetAt(2));
        storage.append(packetAt(3));

        List<PacketDetails> page = storage.readPage(1, 2);

        assertThat(page).hasSize(2);
        assertThat(page.get(0).getTimestamp()).isEqualTo(LocalDateTime.of(2025, 1, 1, 0, 0, 1));
        assertThat(page.get(1).getTimestamp()).isEqualTo(LocalDateTime.of(2025, 1, 1, 0, 0, 2));
    }

    @Test
    void shouldKeepTemporalOrder() throws IOException {
        CaptureStorageService storage = new CaptureStorageService(tempDir);
        storage.startSession("eth0", "udp");

        for (int i = 0; i < 10; i++) {
            storage.append(packetAt(i));
        }

        List<PacketDetails> page = storage.readPage(0, 10);

        assertThat(page)
                .extracting(PacketDetails::getTimestamp)
                .isSorted();
    }

    @Test
    void shouldRecoverPacketsOutsideMemoryWindow() throws IOException {
        CaptureStorageService storage = new CaptureStorageService(tempDir);
        storage.startSession("eth0", "icmp");

        for (int i = 0; i < 150; i++) {
            storage.append(packetAt(i));
        }

        List<PacketDetails> recovered = storage.readPage(0, 50);

        assertThat(recovered).hasSize(50);
        assertThat(recovered.getFirst().getTimestamp()).isEqualTo(LocalDateTime.of(2025, 1, 1, 0, 0, 0));
        assertThat(recovered.getLast().getTimestamp()).isEqualTo(LocalDateTime.of(2025, 1, 1, 0, 0, 49));
    }


    @Test
    void shouldCreateUniqueDirectoryPerSessionStart() throws IOException {
        CaptureStorageService storage = new CaptureStorageService(tempDir);

        storage.startSession("eth0", "tcp");
        Path first = storage.getActiveSessionDir();
        storage.closeSession();

        storage.startSession("eth0", "tcp");
        Path second = storage.getActiveSessionDir();
        storage.closeSession();

        assertThat(first).isNotEqualTo(second);
        assertThat(Files.exists(first)).isTrue();
        assertThat(Files.exists(second)).isTrue();
    }

    @Test
    void shouldWriteMetadataOnClose() throws IOException {
        CaptureStorageService storage = new CaptureStorageService(tempDir);
        storage.startSession("eth0", "arp");
        storage.append(packetAt(1));
        Path sessionDir = storage.getActiveSessionDir();

        storage.closeSession();

        Path metadata = sessionDir.resolve("metadata.properties");
        assertThat(Files.exists(metadata)).isTrue();
        String content = Files.readString(metadata);
        assertThat(content).contains("session.id=");
        assertThat(content).contains("interface=eth0");
        assertThat(content).contains("filter=arp");
        assertThat(content).contains("start=");
        assertThat(content).contains("end=");
    }

    private static PacketDetails packetAt(int seconds) {
        return PacketDetails.fromStorage(
                LocalDateTime.of(2025, 1, 1, 0, 0, 0).plusSeconds(seconds),
                "TCP",
                "IPv4",
                "10.0.0.1",
                "10.0.0.2",
                1234,
                80,
                64,
                "SYN",
                "aa bb cc"
        );
    }
}
