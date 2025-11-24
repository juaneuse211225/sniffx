# SniffX

SniffX es un analizador de red simple escrito en JavaFX y Pcap4J. Permite capturar, visualizar y clasificar paquetes en tiempo real, mostrando detalles como protocolo, IP de origen y destino.

## Características principales

- **Captura en tiempo real:** Intercepta paquetes de red desde interfaces seleccionadas.
- **Visualización amigable:** Interfaz gráfica construida con JavaFX para mostrar los datos capturados de forma clara.
- **Clasificación de paquetes:** Identifica y organiza los paquetes según su protocolo (TCP, UDP, ICMP, etc.).
- **Detalles de tráfico:** Presenta información esencial como IP de origen, IP de destino, puertos y detalles de protocolo.
- **Filtrado por tipo (en desarrollo):** Próximamente, filtros para mostrar solo determinados protocolos o direcciones específicas.
- **Estadísticas en vivo:** Monitorea el tráfico en tiempo real con estadísticas dinámicas.

## Instalación

1. Clona el repositorio:

   ```sh
   git clone https://github.com/juaneuse211225/sniffx.git
   ```

2. Compila el proyecto con tu IDE favorito o con Maven:

   ```sh
   mvn clean install
   ```

3. Ejecuta la aplicación:

   ```sh
   java -jar target/sniffx.jar
   ```

## Requisitos

- Java 21 o superior.
- JavaFX.
- Pcap4J (ya incluido como dependencia).

## Uso

1. Selecciona la interfaz de red a analizar.
2. Inicia la captura para ver los paquetes en tiempo real.
3. Utiliza las funciones de exploración para analizar los datos según tus necesidades.

## Contribuir

Si quieres aportar mejoras, por favor crea un fork y envía tu PR contra la rama `develop`.

## Licencia

**Por definir**. Es probable que en el futuro el proyecto adopte la licencia MIT.

---

*Proyecto desarrollado por juaneuse211225 inspirado en la funcionalidad de Wireshark. No utiliza ni comparte código de Wireshark.*