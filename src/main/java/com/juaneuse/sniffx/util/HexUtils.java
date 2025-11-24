package com.juaneuse.sniffx.util;

public class HexUtils {

    public static String toHexDump(byte[] data) {

        if (data == null || data.length == 0) {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        int offset = 0;

        for (int i = 0; i < data.length; i += 16) {

            sb.append(String.format("%04X  ", offset));

            for (int j = 0; j < 16; j++) {
                if (i + j < data.length) {
                    sb.append(String.format("%02X ", data[i + j]));
                } else {
                    sb.append("   ");
                }
            }

            sb.append(" ");

            for (int j = 0; j < 16; j++) {
                if (i + j < data.length) {
                    byte b = data[i + j];
                    sb.append((b >= 32 && b <= 126) ? (char) b : '.');
                }
            }

            sb.append("\n");
            offset += 16;
        }

        return sb.toString();
    }
}
