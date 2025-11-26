package com.juaneuse.sniffx.filter;

/**
 *
 * @author juaneuse
 */
public class SimpleFilterParser {

    public static String parse(String input) {
        if (input == null || input.isBlank()) return "";

        String protocol = null;
        String host = null;
        boolean src = false;
        boolean dst = false;
        String port = null;

        String[] tokens = input.split("\\s+");

        for (String t : tokens) {
            String token = t.trim();

            // Protocolos
            if (token.equalsIgnoreCase("tcp") ||
                token.equalsIgnoreCase("udp") ||
                token.equalsIgnoreCase("icmp") ||
                token.equalsIgnoreCase("arp") ||
                token.equalsIgnoreCase("ip")
            ) {
                protocol = token.toLowerCase();
                continue;
            }

            // Host simple
            if (token.startsWith("@")) {
                host = token.substring(1);
                continue;
            }

            // src:@IP
            if (token.startsWith("src:@")) {
                host = token.substring(5);
                src = true;
                continue;
            }

            // dst:@IP
            if (token.startsWith("dst:@")) {
                host = token.substring(5);
                dst = true;
                continue;
            }

            // Puerto o rango
            if (token.matches("\\d+") || token.matches("\\d+-\\d+")) {
                port = token;
            }
        }

        StringBuilder bpf = new StringBuilder();

        if (protocol != null) {
            bpf.append(protocol);
        }

        if (port != null) {
            if (bpf.length() > 0) bpf.append(" and ");

            if (port.contains("-")) {
                String[] r = port.split("-");
                bpf.append("portrange ").append(r[0]).append("-").append(r[1]);
            } else {
                bpf.append("port ").append(port);
            }
        }

        if (host != null) {
            if (bpf.length() > 0) bpf.append(" and ");

            if (src) bpf.append("src host ").append(host);
            else if (dst) bpf.append("dst host ").append(host);
            else bpf.append("host ").append(host);
        }

        return bpf.toString();
    }
}

