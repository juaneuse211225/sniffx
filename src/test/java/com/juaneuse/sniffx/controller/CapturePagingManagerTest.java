package com.juaneuse.sniffx.controller;

import com.juaneuse.sniffx.model.PacketDetails;
import com.juaneuse.sniffx.storage.CaptureStorageService;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class CapturePagingManagerTest {

    @Test
    void shouldAppendAndKeepWindowBounded() throws IOException {
        CaptureStorageService storage = mock(CaptureStorageService.class);
        ObservableList<PacketDetails> packetList = FXCollections.observableArrayList();
        CapturePagingManager manager = new CapturePagingManager(storage, packetList, 2, 10);

        PacketDetails first = packetAt(1);
        PacketDetails second = packetAt(2);
        PacketDetails third = packetAt(3);

        manager.append(first);
        manager.append(second);
        manager.append(third);

        assertThat(packetList)
                .extracting(PacketDetails::getTimestamp)
                .containsExactly(second.getTimestamp(), third.getTimestamp());
        verify(storage, times(3)).append(any(PacketDetails.class));
    }

    @Test
    void shouldLoadPreviousPageAndKeepWindowBounded() throws IOException {
        CaptureStorageService storage = mock(CaptureStorageService.class);
        ObservableList<PacketDetails> packetList = FXCollections.observableArrayList(packetAt(3), packetAt(4));
        CapturePagingManager manager = new CapturePagingManager(storage, packetList, 2, 2);

        manager.append(packetAt(5));
        when(storage.readPage(0, 1)).thenReturn(List.of(packetAt(2)));

        manager.loadPreviousPage();

        assertThat(packetList)
                .extracting(PacketDetails::getTimestamp)
                .containsExactly(packetAt(2).getTimestamp(), packetAt(4).getTimestamp());
        verify(storage).readPage(0, 1);
    }

    @Test
    void shouldDelegateSessionOperations() throws IOException {
        CaptureStorageService storage = mock(CaptureStorageService.class);
        ObservableList<PacketDetails> packetList = FXCollections.observableArrayList(packetAt(1));
        CapturePagingManager manager = new CapturePagingManager(storage, packetList, 100, 20);

        manager.startSession("eth0", "tcp");
        manager.closeSession();

        assertThat(packetList).isEmpty();
        verify(storage).startSession("eth0", "tcp");
        verify(storage).closeSession();
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
