package com.juaneuse.sniffx.controller;

import com.juaneuse.sniffx.model.PacketInfo;
import com.juaneuse.sniffx.sniffer.PacketObserver;
import com.juaneuse.sniffx.sniffer.PacketSniffer;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.util.List;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.transformation.SortedList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.scene.control.SplitPane;
import javafx.scene.control.TableCell;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.GridPane;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;

public class SnifferController implements PacketObserver {

    private PacketSniffer packetSniffer;
    private boolean running = false;
    private List<PcapNetworkInterface> listInterfaces;
    private String interfaceName;
    private final ObservableList<PacketInfo> packetList = FXCollections.observableArrayList();
    private boolean desplegado = true;

    @FXML
    private Button btnPaneInfo;

    @FXML
    private Button btnStatus;

    @FXML
    private GridPane gridInfoPacket;

    @FXML
    private AnchorPane panelInferior;

    @FXML
    private AnchorPane panelSuperior;

    @FXML
    private SplitPane splitPane;

    @FXML
    private TableColumn<PacketInfo, Integer> columnLegth;

    @FXML
    private TableColumn<PacketInfo, String> columnProtocol;

    @FXML
    private TableColumn<PacketInfo, LocalDateTime> columnTimestamp;

    @FXML
    private TableColumn<PacketInfo, String> ColumnDest;

    @FXML
    private TableColumn<PacketInfo, String> ColumnSour;

    @FXML
    private ComboBox<String> comboInterfaces;

    @FXML
    private TableView<PacketInfo> tablePackets;

    @FXML
    void initialize() {
        columnLegth.setCellValueFactory(new PropertyValueFactory<>("length"));
        columnProtocol.setCellValueFactory(new PropertyValueFactory<>("protocol"));
        ColumnSour.setCellValueFactory(new PropertyValueFactory<>("srcIp"));
        ColumnDest.setCellValueFactory(new PropertyValueFactory<>("dstIp"));

        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("MM/dd - HH:mm:ss.SSS");

        columnTimestamp.setCellFactory(column -> new TableCell<PacketInfo, LocalDateTime>() {
            @Override
            protected void updateItem(LocalDateTime item, boolean empty) {
                super.updateItem(item, empty);
                if (empty || item == null) {
                    setText(null);
                } else {
                    setText(item.format(formatter));
                }
            }
        });
        columnTimestamp.setCellValueFactory(new PropertyValueFactory<>("timestamp"));

        //  Asignar SortedList a TableView
        SortedList<PacketInfo> sortedList = new SortedList<>(packetList);
        sortedList.comparatorProperty().bind(tablePackets.comparatorProperty());

        tablePackets.setItems(sortedList);

        //  suscribirse al observador
        packetSniffer = new PacketSniffer();
        packetSniffer.addObserver(this);

        loadInterfacesCombo();

        double max = 0.40;

        splitPane.getDividers().get(0).positionProperty().addListener((obs, oldPos, newPos) -> {
            if (newPos.doubleValue() < max) {
                splitPane.getDividers().get(0).setPosition(max);
            }
        });

        splitPane.getDividers().get(0).positionProperty().addListener((obs, oldPos, newPos) -> {
            final double SNAP_THRESHOLD = 0.85;
            double currentPosition = newPos.doubleValue();

            if (currentPosition > SNAP_THRESHOLD) {
                splitPane.getDividers().get(0).setPosition(1.0);
                desplegado = false;
            } else {
                desplegado = true;
            }
        });

    }

    private void loadInterfacesCombo() {
        ObservableList<String> ListInterfaceName = FXCollections.observableArrayList();
        try {
            listInterfaces = packetSniffer.listInterfaces();

            for (PcapNetworkInterface networkInterface : listInterfaces) {
                ListInterfaceName.add(networkInterface.getName());
            }
        } catch (PcapNativeException ex) {
            System.out.println(ex.getMessage());
        }

        comboInterfaces.setItems(ListInterfaceName);
    }

    @FXML
    void onInterfaceSelected(ActionEvent event) {
        interfaceName = comboInterfaces.getValue();
    }

    @FXML
    void onTracked(ActionEvent event) {
        running = !running;
        if (running) {
            try {
                if (interfaceName == null || interfaceName.isEmpty()) {
                    Alert alert
                            = new Alert(AlertType.WARNING, "Seleccione una interfaz primero.");
                    alert.showAndWait();
                    running = false;
                    return;
                }
                packetList.clear();
                packetSniffer.start(interfaceName, listInterfaces);
                btnStatus.setText("Detener");
            } catch (PcapNativeException pe) {
                new Alert(AlertType.ERROR, "Error al iniciar captura: " + pe.getMessage()).showAndWait();
                running = false;
            }

        } else {
            try {
                packetSniffer.stop();
                btnStatus.setText("Iniciar");
            } catch (NotOpenException ex) {
                new Alert(AlertType.ERROR, "Error al detener captura: " + ex.getMessage()).showAndWait();
            }
        }
    }

    @FXML
    void onView(ActionEvent event) {

        splitPane.getDividers().get(0).setPosition(desplegado ? 1.0 : 0.6);
        desplegado = !desplegado;

    }

    @Override
    public void onPacketReceived(PacketInfo packet) {
        Platform.runLater(() -> {
            packetList.add(packet);
            if (packetList.size() > 100) {
                packetList.remove(0);
            }
        });
    }
}
