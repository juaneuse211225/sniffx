package com.juaneuse.sniffx.controller;

import com.juaneuse.sniffx.filter.BpfFilterBuilder;
import com.juaneuse.sniffx.model.PacketDetails;
import com.juaneuse.sniffx.model.PacketInfo;
import com.juaneuse.sniffx.runtime.SnifferState;
import com.juaneuse.sniffx.storage.CaptureStorageService;
import com.juaneuse.sniffx.sniffer.PacketObserver;
import com.juaneuse.sniffx.runtime.ErrorState;
import com.juaneuse.sniffx.runtime.SnifferStateObserver;
import java.io.IOException;
import java.time.LocalDateTime;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.transformation.SortedList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Label;
import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;
import javafx.scene.control.ComboBox;
import javafx.scene.control.SplitPane;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TextField;
import javafx.scene.control.ToggleButton;
import javafx.scene.control.ScrollBar;
import javafx.scene.layout.GridPane;
import javafx.animation.KeyFrame;
import javafx.animation.Timeline;
import javafx.util.Duration;

public class SnifferController implements PacketObserver, SnifferStateObserver {

    private final SniffingService sniffService = new SniffingService();
    private final ObservableList<PacketDetails> packetList = FXCollections.observableArrayList();
    private final CapturePagingManager capturePagingManager =
            new CapturePagingManager(new CaptureStorageService(), packetList, SnifferUiConfig.MAX_IN_MEMORY, SnifferUiConfig.PAGE_SIZE);
    private final PacketBacklogBuffer packetBacklogBuffer = new PacketBacklogBuffer();
    private final PacketUiDrainManager packetUiDrainManager =
            new PacketUiDrainManager(
                    packetBacklogBuffer,
                    packetList,
                    SnifferUiConfig.DRAIN_BATCH_SIZE,
                    SnifferUiConfig.MAX_UI_PACKETS,
                    SnifferUiConfig.MAX_QUEUE_SIZE
            );
    private final Timeline packetDrainTimeline = new Timeline(
            new KeyFrame(Duration.millis(SnifferUiConfig.DRAIN_INTERVAL_MS), event -> drainPendingPackets())
    );
    private boolean desplegado = false;
    private boolean overloadWarningVisible = false;
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
    @FXML
    private Label labelQueueStatus;

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

        // Configuración inicial
        textFilterBpf.setPromptText("Ej: tcp @192.168.1.1 80-443");
        configureService();
        packetDrainTimeline.setCycleCount(Timeline.INDEFINITE);
        packetDrainTimeline.play();
        updateQueueStatus(false);
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

        tablePackets.skinProperty().addListener((obs, oldSkin, newSkin) -> configureIncrementalLoading());
    }

    private void configureIncrementalLoading() {
        ScrollBar verticalBar = (ScrollBar) tablePackets.lookup(".scroll-bar:vertical");
        if (verticalBar == null) {
            return;
        }

        verticalBar.valueProperty().addListener((obs, oldVal, newVal) -> {
            if (newVal.doubleValue() <= 0.05) {
                loadPreviousPage();
            }
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
        capturePagingManager.resetWindow();
        packetUiDrainManager.reset();
        updateQueueStatus(false);
        detailRenderer.clear();

        // Delegamos al servicio
        try {
            String bpf = BpfFilterBuilder.build(textFilterBpf.getText());
            capturePagingManager.startSession(interfaz, bpf);
            sniffService.startCapture(interfaz, bpf);
        } catch (IllegalArgumentException e) {
            btnStatus.setSelected(false);
            new Alert(AlertType.WARNING, "Filtro inválido: " + e.getMessage()).showAndWait();
        } catch (IOException e) {
            btnStatus.setSelected(false);
            mostrarAlertaError("No se pudo iniciar almacenamiento de captura: " + e.getMessage());
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
            PacketDetails details = PacketDetails.from(packet);
            try {
                capturePagingManager.append(details);
            } catch (IOException e) {
                mostrarAlertaError("Error persistiendo paquete: " + e.getMessage());
                packetUiDrainManager.enqueueFallback(details);
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
            if (!isRunning) {
                closeStorageSession();
            }
            actualizarBotonEstado(isRunning);
        });
    }

    private void loadPreviousPage() {
        try {
            capturePagingManager.loadPreviousPage();
        } catch (IOException e) {
            mostrarAlertaError("Error cargando página de paquetes: " + e.getMessage());
        }
    }

    private void closeStorageSession() {

        try {
            capturePagingManager.closeSession();
        } catch (IOException e) {
            mostrarAlertaError("No se pudo cerrar sesión de captura: " + e.getMessage());
        }
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

    private void drainPendingPackets() {
        boolean overloaded = packetUiDrainManager.drainPendingPackets();
        updateQueueStatus(overloaded);
    }

    private void updateQueueStatus(boolean overloaded) {
        if (labelQueueStatus == null) {
            return;
        }

        if (overloaded) {
            labelQueueStatus.setText("Sobrecarga: la vista está descartando paquetes de cola");
            labelQueueStatus.setStyle("-fx-text-fill: #d35400; -fx-font-weight: bold;");
            overloadWarningVisible = true;
            return;
        }

        if (overloadWarningVisible || packetUiDrainManager.isQueueEmpty()) {
            labelQueueStatus.setText("Estado de cola: normal");
            labelQueueStatus.setStyle("-fx-text-fill: #2e7d32;");
            overloadWarningVisible = false;
        }
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
