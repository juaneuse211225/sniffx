package com.juaneuse.sniffx.controller;

import com.juaneuse.sniffx.model.PacketDetails;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.scene.layout.GridPane;

/**
 *
 * @author juaneuse
 */
public class PacketDetailRenderer {

    private final GridPane container;

    public PacketDetailRenderer(GridPane container) {
        this.container = container;
    }

    public void render(PacketDetails packet) {
        container.getChildren().clear();
        
        if (packet == null) return;

        int row = 0;
        // Renderizamos campos condicionalmente
        if (packet.getTimestamp() != null) addRow("Timestamp", packet.getTimestamp().toString(), row++);
        if (packet.getProtocol() != null)  addRow("Protocolo", packet.getProtocol(), row++);
        if (packet.getIpVersion() != null) addRow("Versión IP", packet.getIpVersion(), row++);
        if (packet.getSrcIp() != null)     addRow("IP Origen", packet.getSrcIp(), row++);
        if (packet.getDstIp() != null)     addRow("IP Destino", packet.getDstIp(), row++);
        if (packet.getSrcPort() != null)   addRow("Puerto Origen", packet.getSrcPort().toString(), row++);
        if (packet.getDstPort() != null)   addRow("Puerto Destino", packet.getDstPort().toString(), row++);
        if (packet.getTcpFlags() != null)  addRow("Flags TCP", packet.getTcpFlags(), row++);
        
        if (packet.getHexDump() != null) {
            addHexDumpRow("Hex Dump", packet.getHexDump(), row++);
        }
    }

    public void clear() {
        container.getChildren().clear();
    }

    private void addRow(String labelText, String value, int row) {
        Label key = new Label(labelText + ":");
        key.setStyle("-fx-font-weight: bold;");
        
        Label val = new Label(value);
        val.setStyle("-fx-font-family: 'Consolas';");

        container.addRow(row, key, val);
    }

    private void addHexDumpRow(String labelText, String hexContent, int row) {
        Label key = new Label(labelText + ":");
        key.setStyle("-fx-font-weight: bold;");

        TextArea area = new TextArea(hexContent);
        area.setEditable(false);
        area.setWrapText(false);
        area.setPrefWidth(450);
        area.setMinWidth(450);
        area.setPrefRowCount(10);
        area.setStyle("-fx-font-family: 'Consolas'; -fx-font-size: 12px;");

        // Lógica de portapapeles encapsulada aquí
        area.setOnMouseClicked(e -> {
            ClipboardContent content = new ClipboardContent();
            content.putString(hexContent);
            Clipboard.getSystemClipboard().setContent(content);
        });

        container.add(key, 0, row);
        container.add(area, 1, row);
    }
}
