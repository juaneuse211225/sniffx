package com.juaneuse.sniffx.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class BpfFilterBuilderTest {

    @Test
    void shouldKeepAdvancedBpfExpression() {
        String filter = "(tcp or udp) and src net 192.168.0.0/16 and not port 22";

        assertThat(BpfFilterBuilder.build(filter))
                .isEqualTo("(tcp or udp) and src net 192.168.0.0/16 and not port 22");
    }

    @Test
    void shouldTranslateLegacyAliases() {
        String filter = "tcp src:@192.168.1.10 dst:443 ports:80,8080,1000-2000";

        assertThat(BpfFilterBuilder.build(filter))
                .isEqualTo("tcp src host 192.168.1.10 dst port 443 (port 80 or port 8080 or portrange 1000-2000)");
    }

    @Test
    void shouldRejectUnbalancedParenthesis() {
        assertThatThrownBy(() -> BpfFilterBuilder.build("(tcp and port 80"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Paréntesis desbalanceados");
    }
}
