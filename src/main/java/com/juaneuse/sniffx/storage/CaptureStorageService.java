package com.juaneuse.sniffx.storage;

import com.juaneuse.sniffx.model.PacketDetails;

import java.io.BufferedWriter;
import java.io.Closeable;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.Properties;
import java.util.UUID;

public class CaptureStorageService implements Closeable {

    private static final DateTimeFormatter SESSION_FORMAT = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss");
    private static final String RECORD_VERSION = "v1";

    private final Path baseDir;

    private Path activeSessionDir;
    private BufferedWriter packetWriter;
    private DataOutputStream indexWriter;
    private long currentDataOffset;
    private long recordsCount;
    private SessionMetadata activeMetadata;

    public CaptureStorageService() {
        this(Path.of("captures"));
    }

    public CaptureStorageService(Path baseDir) {
        this.baseDir = Objects.requireNonNull(baseDir, "baseDir");
    }

    public synchronized void startSession(String iface, String filter) throws IOException {
        closeSession();
        Files.createDirectories(baseDir);

        String normalized = sanitize(iface) + "_" + Integer.toHexString(Objects.requireNonNullElse(filter, "").hashCode());
        String timestamp = SESSION_FORMAT.format(LocalDateTime.now());
        String sessionId = UUID.randomUUID().toString();
        activeSessionDir = createUniqueSessionDir(timestamp, normalized, sessionId);

        packetWriter = Files.newBufferedWriter(activeSessionDir.resolve("packets.log"), StandardCharsets.UTF_8);
        indexWriter = new DataOutputStream(Files.newOutputStream(activeSessionDir.resolve("packets.idx")));

        currentDataOffset = 0L;
        recordsCount = 0L;
        activeMetadata = new SessionMetadata(sessionId, iface, Objects.requireNonNullElse(filter, ""), LocalDateTime.now(), null);
    }

    public synchronized long append(PacketDetails packet) throws IOException {
        ensureSessionOpen();
        long offset = recordsCount;

        String line = serialize(packet);
        byte[] bytes = line.getBytes(StandardCharsets.UTF_8);

        indexWriter.writeLong(currentDataOffset);
        packetWriter.write(line);
        packetWriter.newLine();

        currentDataOffset += bytes.length + 1L;
        recordsCount++;
        return offset;
    }

    public synchronized List<PacketDetails> readPage(long offset, int size) throws IOException {
        if (size <= 0) {
            return List.of();
        }

        Path sessionDir = requireSessionDir();
        Path packetsPath = sessionDir.resolve("packets.log");
        Path indexPath = sessionDir.resolve("packets.idx");

        if (!Files.exists(packetsPath) || !Files.exists(indexPath)) {
            return List.of();
        }

        long total = totalRecords();
        if (offset < 0 || offset >= total) {
            return List.of();
        }

        int pageSize = (int) Math.min(size, total - offset);
        List<PacketDetails> page = new ArrayList<>(pageSize);

        try (RandomAccessFile index = new RandomAccessFile(indexPath.toFile(), "r");
             RandomAccessFile data = new RandomAccessFile(packetsPath.toFile(), "r")) {
            for (int i = 0; i < pageSize; i++) {
                long currentOffset = offset + i;
                index.seek(currentOffset * Long.BYTES);
                long recordByteOffset = index.readLong();
                data.seek(recordByteOffset);
                String raw = data.readLine();
                if (raw != null) {
                    page.add(deserialize(new String(raw.getBytes(StandardCharsets.ISO_8859_1), StandardCharsets.UTF_8)));
                }
            }
        }

        return page;
    }

    public synchronized long totalRecords() throws IOException {
        Path sessionDir = requireSessionDir();
        if (indexWriter != null) {
            return recordsCount;
        }

        Path indexPath = sessionDir.resolve("packets.idx");
        if (!Files.exists(indexPath)) {
            return 0L;
        }

        return Files.size(indexPath) / Long.BYTES;
    }

    public synchronized void closeSession() throws IOException {
        IOException failure = null;

        if (packetWriter != null) {
            try {
                packetWriter.flush();
                packetWriter.close();
            } catch (IOException e) {
                failure = e;
            } finally {
                packetWriter = null;
            }
        }

        if (indexWriter != null) {
            try {
                indexWriter.flush();
                indexWriter.close();
            } catch (IOException e) {
                if (failure == null) {
                    failure = e;
                }
            } finally {
                indexWriter = null;
            }
        }

        if (activeSessionDir != null && activeMetadata != null) {
            writeMetadata(activeMetadata.withEnd(LocalDateTime.now()), activeSessionDir.resolve("metadata.properties"));
        }

        activeMetadata = null;
        currentDataOffset = 0L;
        recordsCount = 0L;

        if (failure != null) {
            throw failure;
        }
    }

    public synchronized Path getActiveSessionDir() {
        return activeSessionDir;
    }

    @Override
    public synchronized void close() throws IOException {
        closeSession();
    }

    private Path requireSessionDir() {
        if (activeSessionDir == null) {
            throw new IllegalStateException("No hay sesión de captura activa");
        }
        return activeSessionDir;
    }

    private void ensureSessionOpen() {
        if (packetWriter == null || indexWriter == null) {
            throw new IllegalStateException("La sesión no está abierta para escritura");
        }
    }

    private Path createUniqueSessionDir(String timestamp, String normalized, String sessionId) throws IOException {
        Path candidate = baseDir.resolve(timestamp + "_" + normalized + "_" + sessionId);
        int attempt = 0;
        while (Files.exists(candidate)) {
            attempt++;
            candidate = baseDir.resolve(timestamp + "_" + normalized + "_" + sessionId + "_" + attempt);
        }
        return Files.createDirectory(candidate);
    }

    private static String serialize(PacketDetails packet) {
        return String.join("\t",
                RECORD_VERSION,
                encode(packet.getTimestamp() != null ? packet.getTimestamp().toString() : null),
                encode(packet.getProtocol()),
                encode(packet.getIpVersion()),
                encode(packet.getSrcIp()),
                encode(packet.getDstIp()),
                encode(packet.getSrcPort() != null ? packet.getSrcPort().toString() : null),
                encode(packet.getDstPort() != null ? packet.getDstPort().toString() : null),
                encode(packet.getLength() != null ? packet.getLength().toString() : null),
                encode(packet.getTcpFlags()),
                encode(packet.getHexDump())
        );
    }

    private static PacketDetails deserialize(String line) {
        String[] parts = line.split("\t", -1);
        if (parts.length < 11 || !RECORD_VERSION.equals(parts[0])) {
            throw new IllegalArgumentException("Formato de registro inválido");
        }

        String timestamp = decode(parts[1]);
        return PacketDetails.fromStorage(
                timestamp != null ? LocalDateTime.parse(timestamp) : null,
                decode(parts[2]),
                decode(parts[3]),
                decode(parts[4]),
                decode(parts[5]),
                parseInteger(decode(parts[6])),
                parseInteger(decode(parts[7])),
                parseInteger(decode(parts[8])),
                decode(parts[9]),
                decode(parts[10])
        );
    }

    private static Integer parseInteger(String value) {
        return value == null ? null : Integer.parseInt(value);
    }

    private static String encode(String value) {
        if (value == null) {
            return "-";
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private static String decode(String value) {
        if ("-".equals(value)) {
            return null;
        }
        return new String(Base64.getUrlDecoder().decode(value), StandardCharsets.UTF_8);
    }

    private static String sanitize(String value) {
        if (value == null || value.isBlank()) {
            return "unknown";
        }
        return value.replaceAll("[^a-zA-Z0-9_-]", "_");
    }

    private void writeMetadata(SessionMetadata metadata, Path metadataPath) throws IOException {
        Properties properties = new Properties();
        properties.setProperty("session.id", metadata.sessionId());
        properties.setProperty("interface", metadata.iface());
        properties.setProperty("filter", metadata.filter());
        properties.setProperty("start", metadata.start().toString());
        if (metadata.end() != null) {
            properties.setProperty("end", metadata.end().toString());
        }

        try (OutputStream output = Files.newOutputStream(metadataPath)) {
            properties.store(output, "Capture session metadata");
        }
    }
}
