package com.juaneuse.sniffx.controller;

import com.juaneuse.sniffx.filter.SimpleFilterParser;
import com.juaneuse.sniffx.model.PacketDetails;
import com.juaneuse.sniffx.model.PacketInfo;
import com.juaneuse.sniffx.sniffer.PacketObserver;
import com.juaneuse.sniffx.sniffer.PacketSniffer;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import javafx.application.Platform;
import javafx.beans.property.SimpleIntegerProperty;
import javafx.beans.property.SimpleObjectProperty;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.transformation.SortedList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.SplitPane;
import javafx.scene.control.TableCell;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.control.ToggleButton;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.GridPane;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;

public class SnifferController implements PacketObserver {

    private PacketSniffer packetSniffer;
    private List<PcapNetworkInterface> listInterfaces;
    private String interfaceName;
    private final ObservableList<PacketInfo> packetList = FXCollections.observableArrayList();
    private boolean desplegado = false;

    @FXML
    private Button btnPaneInfo;

    @FXML
    private ToggleButton btnStatus;

    @FXML
    private GridPane gridInfoPacket;

    @FXML
    private AnchorPane panelInferior;

    @FXML
    private AnchorPane panelSuperior;

    @FXML
    private TextField textFilterBpf;

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
        columnLegth.setCellValueFactory(cell -> 
                new SimpleIntegerProperty(cell.getValue().getParsed().length).asObject()
        );
        columnProtocol.setCellValueFactory(cell -> 
                new SimpleStringProperty(cell.getValue().getParsed().protocol)
        );
        ColumnSour.setCellValueFactory(cell -> 
                new SimpleStringProperty(cell.getValue().getParsed().srcIp)
        );
        ColumnDest.setCellValueFactory(cell -> 
                new SimpleStringProperty(cell.getValue().getParsed().dstIp)
        );

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
        columnTimestamp.setCellValueFactory(cell -> 
                new SimpleObjectProperty<>(cell.getValue().getParsed().timestamp)
        );

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

        tablePackets.getSelectionModel().selectedItemProperty().addListener((obs, oldSel, newSel) -> {
            if (newSel != null) {
                mostrarDetalles(newSel);
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
        if (btnStatus.isSelected()) {
            packetList.clear();
            iniciarCapturaConFiltro(textFilterBpf.getText());
        } else {
            detenerCaptura();
        }
    }

    @FXML
    void onView(ActionEvent event) {

        splitPane.getDividers().get(0).setPosition(desplegado ? 1.0 : 0.6);
        desplegado = !desplegado;

    }

    @FXML
    void aplicarFiltro(ActionEvent event) {

        if (btnStatus.isSelected()) {
            detenerCaptura();
            packetList.clear();
            iniciarCapturaConFiltro(textFilterBpf.getText());

        } else {
            iniciarCapturaConFiltro(textFilterBpf.getText());
        }
    }

    @FXML
    void cleanFilter(ActionEvent event) {

        textFilterBpf.setText("");

        if (btnStatus.isSelected()) {
            detenerCaptura();
        }

        iniciarCapturaConFiltro(textFilterBpf.getText());
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

    private void iniciarCapturaConFiltro(String filtro) {
        if (interfaceName == null || interfaceName.isEmpty()) {
            new Alert(AlertType.WARNING, "Seleccione una interfaz primero.").showAndWait();
            return;
        }

        try {
            String bpf = SimpleFilterParser.parse(filtro);
            packetSniffer.start(interfaceName, listInterfaces, bpf);
            btnStatus.setText("Detener");
            btnStatus.setSelected(true);

        } catch (PcapNativeException | NotOpenException ex) {
            new Alert(AlertType.ERROR, "Error al iniciar captura: " + ex.getMessage()).showAndWait();
            btnStatus.setSelected(false);
        }
    }

    private void detenerCaptura() {
        try {
            packetSniffer.stop();
        } catch (NotOpenException ex) {
            new Alert(AlertType.ERROR, "Error al detener captura: " + ex.getMessage()).showAndWait();
        }
        btnStatus.setSelected(false);
        btnStatus.setText("Iniciar");
    }

    private void mostrarDetalles(PacketInfo info) {

        // Limpiar panel
        gridInfoPacket.getChildren().clear();

        PacketDetails d = PacketDetails.from(info);

        int row = 0;

        if (d.getTimestamp() != null) 
            addDetail("Timestamp", d.getTimestamp().toString(), row++);
        
        if (d.getProtocol() != null) 
            addDetail("Protocolo", d.getProtocol(), row++);
        
        if (d.getIpVersion() != null) 
            addDetail("Versión IP", d.getIpVersion(), row++);
        
        if (d.getSrcIp() != null) 
            addDetail("IP Origen", d.getSrcIp(), row++);
        
        if (d.getDstIp() != null) 
            addDetail("IP Destino", d.getDstIp(), row++);
        
        if (d.getSrcPort() != null) 
            addDetail("Puerto Origen", d.getSrcPort().toString(), row++);
        
        if (d.getDstPort() != null) 
            addDetail("Puerto Destino", d.getDstPort().toString(), row++);
        
        if (d.getTcpFlags() != null) 
            addDetail("Flags TCP", d.getTcpFlags(), row++);
        
        if (d.getHexDump() != null) 
            addHexDump("Hex Dump", d.getHexDump(), row++);
        
    }

    private void addDetail(String label, String value, int row) {
        Label key = new Label(label + ":");
        Label val = new Label(value);

        key.setStyle("-fx-font-weight: bold;");
        val.setStyle("-fx-font-family: 'Consolas';");

        gridInfoPacket.addRow(row, key, val);
    }

    private void addHexDump(String label, String value, int row) {

        Label key = new Label(label + ":");
        key.setStyle("-fx-font-weight: bold;");

        TextArea area = new TextArea(value);
        area.setEditable(false);
        area.setWrapText(false);
        area.setPrefWidth(450);
        area.setMinWidth(450);
        area.setPrefRowCount(10);
        area.setStyle("-fx-font-family: 'Consolas'; -fx-font-size: 12px;");

        // Copiar al portapapeles al hacer click
        area.setOnMouseClicked(e -> {
            javafx.scene.input.Clipboard clipboard = javafx.scene.input.Clipboard.getSystemClipboard();
            javafx.scene.input.ClipboardContent content = new javafx.scene.input.ClipboardContent();
            content.putString(value);
            clipboard.setContent(content);

            System.out.println("HexDump copiado al portapapeles.");
        });

        gridInfoPacket.add(key, 0, row);
        gridInfoPacket.add(area, 1, row);
    }

}
