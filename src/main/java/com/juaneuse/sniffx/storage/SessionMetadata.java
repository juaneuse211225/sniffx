package com.juaneuse.sniffx.storage;

import java.time.LocalDateTime;

record SessionMetadata(String sessionId, String iface, String filter, LocalDateTime start, LocalDateTime end) {
    SessionMetadata withEnd(LocalDateTime endedAt) {
        return new SessionMetadata(sessionId, iface, filter, start, endedAt);
    }
}
