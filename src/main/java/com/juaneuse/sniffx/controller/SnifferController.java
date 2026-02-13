package com.juaneuse.sniffx.controller;

import com.juaneuse.sniffx.filter.BpfFilterBuilder;
import com.juaneuse.sniffx.model.PacketDetails;
import com.juaneuse.sniffx.model.PacketInfo;
import com.juaneuse.sniffx.runtime.SnifferState;
import com.juaneuse.sniffx.sniffer.PacketObserver;
import com.juaneuse.sniffx.runtime.ErrorState;
import com.juaneuse.sniffx.runtime.SnifferStateObserver;
import java.time.LocalDateTime;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.transformation.SortedList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;
import javafx.scene.control.ComboBox;
import javafx.scene.control.SplitPane;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TextField;
import javafx.scene.control.ToggleButton;
import javafx.scene.layout.GridPane;

public class SnifferController implements PacketObserver, SnifferStateObserver {

    private final SniffingService sniffService = new SniffingService();

    private final ObservableList<PacketDetails> packetList = FXCollections.observableArrayList();
    private boolean desplegado = false;
    private PacketDetailRenderer detailRenderer;

    // --- Componentes FXML ---
    @FXML
    private ToggleButton btnStatus;
    @FXML
    private GridPane gridInfoPacket;
    @FXML
    private TextField textFilterBpf;
    @FXML
    private SplitPane splitPane;
    @FXML
    private TableView<PacketDetails> tablePackets;
    @FXML
    private ComboBox<String> comboInterfaces;

    // Columnas
    @FXML
    private TableColumn<PacketDetails, Integer> columnLegth;
    @FXML
    private TableColumn<PacketDetails, String> columnProtocol;
    @FXML
    private TableColumn<PacketDetails, LocalDateTime> columnTimestamp;
    @FXML
    private TableColumn<PacketDetails, String> ColumnDest;
    @FXML
    private TableColumn<PacketDetails, String> ColumnSour;

    @FXML
    void initialize() {
        // Inicializar Componentes Visuales delegando la lógica
        PacketTableManager.configure(tablePackets, columnLegth, columnProtocol, ColumnSour, ColumnDest, columnTimestamp);
        this.detailRenderer = new PacketDetailRenderer(gridInfoPacket);

        // Configurar Binding de Datos
        SortedList<PacketDetails> sortedData = new SortedList<>(packetList);
        sortedData.comparatorProperty().bind(tablePackets.comparatorProperty());
        tablePackets.setItems(sortedData);

        // Listeners de UI
        setupListeners();

        // Configurar Servicios
        loadInterfacesCombo();
        sniffService.addPacketObserver(this);
        sniffService.addStateObserver(this);

        // Configuración inicial
        textFilterBpf.setPromptText("Ej: tcp @192.168.1.1 80-443");
        configureService();
    }

    private void setupListeners() {
        // Listener de Selección en Tabla
        tablePackets.getSelectionModel().selectedItemProperty().addListener((obs, old, selected) -> {
            if (selected != null) {
                detailRenderer.render(selected);
            }
        });

        // Listener del SplitPane (Responsividad básica)
        splitPane.getDividers().get(0).positionProperty().addListener((obs, oldVal, newVal) -> {
            double pos = newVal.doubleValue();
            // Evitar que el panel sea muy pequeño
            if (pos < 0.40) {
                splitPane.setDividerPosition(0, 0.40);
            }

            // Detectar si se colapsó manualmente
            desplegado = (pos <= 0.85);
        });
    }

    @FXML
    void onTracked(ActionEvent event) {
        // El botón es Toggle, así que actuamos según su estado visual
        if (btnStatus.isSelected()) {
            ejecutarCaptura();
        } else {
            sniffService.stopCapture();
        }
    }

    @FXML
    void aplicarFiltro(ActionEvent event) {
        // Al aplicar filtro, reiniciamos la captura
        ejecutarCaptura();
    }

    @FXML
    void cleanFilter(ActionEvent event) {
        textFilterBpf.clear();
        ejecutarCaptura();
    }

    @FXML
    void onInterfaceSelected(ActionEvent event) {
        // Si hay una captura corriendo y cambiamos interfaz, reiniciamos
        if (btnStatus.isSelected()) {
            ejecutarCaptura();
        }
    }

    @FXML
    void onView(ActionEvent event) {
        // Toggle simple del panel lateral
        splitPane.setDividerPosition(0, desplegado ? 1.0 : 0.6);
        desplegado = !desplegado;
    }

    private void ejecutarCaptura() {
        String interfaz = comboInterfaces.getValue();

        if (interfaz == null || interfaz.isEmpty()) {
            btnStatus.setSelected(false);
            new Alert(AlertType.WARNING, "Por favor, seleccione una interfaz de red.").showAndWait();
            return;
        }

        // Limpiamos datos viejos
        packetList.clear();
        detailRenderer.clear();

        // Delegamos al servicio
        try {
            String bpf = BpfFilterBuilder.build(textFilterBpf.getText());
            sniffService.startCapture(interfaz, bpf);
        } catch (IllegalArgumentException e) {
            btnStatus.setSelected(false);
            new Alert(AlertType.WARNING, "Filtro inválido: " + e.getMessage()).showAndWait();
        }
    }

    private void loadInterfacesCombo() {
        // Aseguramos que la lista sea Observable para JavaFX
        comboInterfaces.setItems(FXCollections.observableArrayList(sniffService.getInterfaceNames()));
        if (!comboInterfaces.getItems().isEmpty()) {
            comboInterfaces.getSelectionModel().selectFirst();
        }
    }

    @Override
    public void onPacketReceived(PacketInfo packet) {
        // Siempre usar Platform.runLater para modificar la ObservableList que está atada a la UI
        Platform.runLater(() -> {
            packetList.add(PacketDetails.from(packet));

            // Mantener la lista en un tamaño manejable para no saturar la memoria
            if (packetList.size() > 100) {
                packetList.remove(0);
            }
        });
    }

    @Override
    public void onStateChanged(SnifferState newState) {
        Platform.runLater(() -> {
            // Manejo de Error
            if (newState instanceof ErrorState error) {
                mostrarAlertaError(error.getMessage());
                // Forzamos estado visual de "Detenido"
                actualizarBotonEstado(false);
                return;
            }

            // Actualización visual según estado
            boolean isRunning = newState.name().equalsIgnoreCase("RUNNING");
            actualizarBotonEstado(isRunning);
        });
    }

    private void iniciarCapturaConFiltro(String filtro) {
        String selectedInterface = comboInterfaces.getValue();

        if (selectedInterface == null || selectedInterface.isEmpty()) {
            // Si no hay interfaz, revertimos el botón visualmente y avisamos
            btnStatus.setSelected(false);
            new Alert(AlertType.WARNING, "Seleccione una interfaz primero.").showAndWait();
            return;
        }

        packetList.clear();
        // El servicio ahora usa el RuntimeContext internamente
        try {
            sniffService.startCapture(selectedInterface, BpfFilterBuilder.build(filtro));
        } catch (IllegalArgumentException e) {
            btnStatus.setSelected(false);
            new Alert(AlertType.WARNING, "Filtro inválido: " + e.getMessage()).showAndWait();
        }
    }

    private void detenerCaptura() {
        sniffService.stopCapture();
        btnStatus.setSelected(false);
        btnStatus.setText("Iniciar");
    }

    private void configureService() {
        sniffService.addPacketObserver(this);
        sniffService.addStateObserver(this); // Escuchar cambios de estado
    }

    private void actualizarBotonEstado(boolean capturing) {
        btnStatus.setSelected(capturing);
        btnStatus.setText(capturing ? "Detener" : "Iniciar");

        // Deshabilitar controles sensibles durante la captura si lo deseas
        comboInterfaces.setDisable(capturing);
    }

    private void mostrarAlertaError(String mensaje) {
        Alert alert = new Alert(AlertType.ERROR);
        alert.setTitle("Error de Captura");
        alert.setHeaderText("El motor de sniffing se ha detenido");
        alert.setContentText(mensaje);
        alert.showAndWait();
    }
}
