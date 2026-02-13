package com.juaneuse.sniffx.filter;

import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Builder de filtros BPF con compatibilidad retro para la sintaxis simplificada de SniffX.
 */
public final class BpfFilterBuilder {

    private static final Pattern SRC_HOST_ALIAS = Pattern.compile("(?i)\\bsrc:@([^\\s()]+)");
    private static final Pattern DST_HOST_ALIAS = Pattern.compile("(?i)\\bdst:@([^\\s()]+)");
    private static final Pattern HOST_ALIAS = Pattern.compile("(?<!:)@([^\\s()]+)");
    private static final Pattern SRC_PORT_ALIAS = Pattern.compile("(?i)\\bsrc:(\\d+)");
    private static final Pattern DST_PORT_ALIAS = Pattern.compile("(?i)\\bdst:(\\d+)");
    private static final Pattern SRC_RANGE_ALIAS = Pattern.compile("(?i)\\bsrc:(\\d+)-(\\d+)");
    private static final Pattern DST_RANGE_ALIAS = Pattern.compile("(?i)\\bdst:(\\d+)-(\\d+)");
    private static final Pattern PORT_LIST_ALIAS = Pattern.compile("(?i)\\bports:([0-9,\\-]+)");

    private static final Set<String> ALLOWED_WORDS = Set.of(
            "and", "or", "not", "host", "src", "dst", "port", "portrange", "net", "mask", "proto", "protochain",
            "ether", "broadcast", "multicast", "vlan", "inbound", "outbound", "gateway", "less", "greater",
            "tcp", "udp", "icmp", "icmp6", "arp", "rarp", "ip", "ip6"
    );

    private BpfFilterBuilder() {
    }

    public static String build(String input) {
        if (input == null || input.isBlank()) {
            return "";
        }

        String normalized = normalizeAliases(input.trim());
        validateParentheses(normalized);
        validateTokens(normalized);
        return normalized;
    }

    private static String normalizeAliases(String input) {
        String result = input;
        result = replaceAll(SRC_HOST_ALIAS, result, "src host $1");
        result = replaceAll(DST_HOST_ALIAS, result, "dst host $1");
        result = replaceAll(HOST_ALIAS, result, "host $1");

        result = replaceAll(SRC_RANGE_ALIAS, result, "src portrange $1-$2");
        result = replaceAll(DST_RANGE_ALIAS, result, "dst portrange $1-$2");
        result = replaceAll(SRC_PORT_ALIAS, result, "src port $1");
        result = replaceAll(DST_PORT_ALIAS, result, "dst port $1");

        Matcher listMatcher = PORT_LIST_ALIAS.matcher(result);
        StringBuffer sb = new StringBuffer();
        while (listMatcher.find()) {
            String replacement = expandPortList(listMatcher.group(1));
            listMatcher.appendReplacement(sb, Matcher.quoteReplacement(replacement));
        }
        listMatcher.appendTail(sb);

        return sb.toString().replaceAll("\\s+", " ").trim();
    }

    private static String replaceAll(Pattern pattern, String input, String replacement) {
        return pattern.matcher(input).replaceAll(replacement);
    }

    private static String expandPortList(String list) {
        String[] chunks = list.split(",");
        StringBuilder builder = new StringBuilder("(");
        for (int i = 0; i < chunks.length; i++) {
            if (i > 0) {
                builder.append(" or ");
            }
            String value = chunks[i].trim();
            if (value.contains("-")) {
                builder.append("portrange ").append(value);
            } else {
                builder.append("port ").append(value);
            }
        }
        builder.append(")");
        return builder.toString();
    }

    private static void validateParentheses(String filter) {
        int depth = 0;
        for (char c : filter.toCharArray()) {
            if (c == '(') {
                depth++;
            } else if (c == ')') {
                depth--;
                if (depth < 0) {
                    throw new IllegalArgumentException("Paréntesis desbalanceados en el filtro.");
                }
            }
        }

        if (depth != 0) {
            throw new IllegalArgumentException("Paréntesis desbalanceados en el filtro.");
        }
    }

    private static void validateTokens(String filter) {
        String[] tokens = filter.split("\\s+");
        for (String token : tokens) {
            String clean = token.replace("(", "").replace(")", "").trim();
            if (clean.isEmpty()) {
                continue;
            }

            if (clean.matches("\\d+") || clean.matches("\\d+-\\d+")) {
                continue;
            }

            if (clean.matches("[0-9a-fA-F:./]+") || clean.matches("[a-zA-Z0-9._/-]+")) {
                if (!clean.matches("[A-Za-z]+") || ALLOWED_WORDS.contains(clean.toLowerCase(Locale.ROOT))) {
                    continue;
                }
            }

            throw new IllegalArgumentException("Token no soportado en filtro: " + clean);
        }
    }
}
