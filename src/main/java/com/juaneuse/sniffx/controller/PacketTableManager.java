package com.juaneuse.sniffx.controller;

import com.juaneuse.sniffx.model.PacketDetails;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import javafx.beans.property.SimpleIntegerProperty;
import javafx.beans.property.SimpleObjectProperty;
import javafx.beans.property.SimpleStringProperty;
import javafx.scene.control.TableCell;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;

/**
 *
 * @author juaneuse
 */
public class PacketTableManager {

    private static final DateTimeFormatter TIME_FMT = DateTimeFormatter.ofPattern("MM/dd - HH:mm:ss.SSS");

    public static void configure(
            TableView<PacketDetails> table,
            TableColumn<PacketDetails, Integer> colLen,
            TableColumn<PacketDetails, String> colProto,
            TableColumn<PacketDetails, String> colSrc,
            TableColumn<PacketDetails, String> colDst,
            TableColumn<PacketDetails, LocalDateTime> colTime
    ) {
        // Mapeo de datos simple
        colLen.setCellValueFactory(c -> new SimpleIntegerProperty(c.getValue().getLength()).asObject());
        colProto.setCellValueFactory(c -> new SimpleStringProperty(c.getValue().getProtocol()));
        colSrc.setCellValueFactory(c -> new SimpleStringProperty(c.getValue().getSrcIp()));
        colDst.setCellValueFactory(c -> new SimpleStringProperty(c.getValue().getDstIp()));
        
        // Configuración especial para la fecha
        configureDateColumn(colTime);
    }

    private static void configureDateColumn(TableColumn<PacketDetails, LocalDateTime> column) {
        column.setCellValueFactory(c -> new SimpleObjectProperty<>(c.getValue().getTimestamp()));
        
        column.setCellFactory(col -> new TableCell<>() {
            @Override
            protected void updateItem(LocalDateTime item, boolean empty) {
                super.updateItem(item, empty);
                if (empty || item == null) {
                    setText(null);
                } else {
                    setText(item.format(TIME_FMT));
                }
            }
        });
    }
}