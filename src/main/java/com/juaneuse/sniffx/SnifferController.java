package com.juaneuse.sniffx;

import com.juaneuse.sniffx.model.PacketInfo;
import com.juaneuse.sniffx.sniffer.PacketObserver;
import com.juaneuse.sniffx.sniffer.PacketSniffer;
import java.time.LocalDateTime;
import java.util.Comparator;
import java.util.List;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.cell.PropertyValueFactory;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;

public class SnifferController implements PacketObserver {
    
    private PacketSniffer packetSniffer;
    private boolean running = false;
    private List<PcapNetworkInterface> listInterfaces;
    private String interfaceName;
    private final ObservableList<PacketInfo> packetList = FXCollections.observableArrayList();

    @FXML
    private Button btnStatus;

    @FXML
    private TableColumn<PacketInfo, Integer> columnLegth;

    @FXML
    private TableColumn<PacketInfo, String> columnProtocol;

    @FXML
    private TableColumn<PacketInfo, LocalDateTime> columnTimestamp;

    @FXML
    private ComboBox<String> comboInterfaces;

    @FXML
    private TableView<PacketInfo> tablePackets;
    
    @FXML
    void initialize() {
        columnLegth.setCellValueFactory(new PropertyValueFactory<>("length"));
        columnProtocol.setCellValueFactory(new PropertyValueFactory<>("protocol"));
        columnTimestamp.setCellValueFactory(new PropertyValueFactory<>("timestamp"));
        
        tablePackets.setItems(packetList);
        
        packetSniffer = new PacketSniffer();
        packetSniffer.addObserver(this);
        
        ObservableList<String> ListInterfaceName = FXCollections.observableArrayList();
        try {
            listInterfaces = packetSniffer.listInterfaces();
            
            
            for(PcapNetworkInterface networkInterface : listInterfaces){
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
        if(running){
            try{
                packetList.removeAll();
                packetSniffer.start(interfaceName, listInterfaces);
            }catch(PcapNativeException pe){
                System.out.println(pe.getMessage());
            }
            
        }else{
            try {
                packetSniffer.stop();
            } catch (NotOpenException ex) {
                System.out.println(ex.getMessage());
            }
        }
    }

    @Override
    public void onPacketReceived(PacketInfo packet) {
        Platform.runLater(() -> {
            packetList.add(packet);
            FXCollections.sort(packetList, Comparator.comparing(PacketInfo::getTimestamp).reversed());
            if(packetList.size() > 100) packetList.removeFirst();
        });
    }
    
    

}
