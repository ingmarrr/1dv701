import java.net.DatagramSocket;
import java.net.DatagramPacket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.util.Date;
import java.text.SimpleDateFormat;

public class App {
    private static final int TFTPORT = 4970;
    private static final int BUFSIZE = 516;
    private static final String READDIR = "/Users/ingmarfalk/uni/ComputerNetworks_1DV701/a3/read/";
    private static final String WRITEDIR = "/Users/ingmarfalk/uni/ComputerNetworks_1DV701/a3/write/";
    private int blockNumber = 1;

    public enum OpCode {
        Rrq,
        Wrq,
        Data,
        Ack,
        Err;

        public int toInt() {
            return ordinal() + 1;
        }

        public byte toByte() {
            return (byte) (ordinal() + 1);
        }
    }

    public enum Error {
        Undefined("Undefined error code."),
        FileNotFound("File not found."),
        AccessViolation("Access violation."),
        LostAccess("Disk full or allocation exceeded."),
        IllegalTFTPOperation("Illegal TFTP operation."),
        UnknownTID("Unknown transfer ID."),
        FileAlreadyExists("File already exists."),
        NoSuchUser("No such user.");

        private final String msg;

        Error(String msg) {
            this.msg = msg;
        }

        public String getMsg() {
            return msg;
        }
    }

    public static void main(String[] args) {

        if (args.length > 0) {
            log("ERROR", "usage: java " + App.class.getCanonicalName());
            System.exit(0);
        }

        // checkTry("Failed to start Application", () -> {
        // log("INFO", "Starting server...");
        // App server = new App();
        // server.start();
        // });
        try {
            log("INFO", "Starting server...");
            App server = new App();
            server.start();
        } catch (SocketException e) {
            e.printStackTrace();
        }

    }

    private void start() throws SocketException {

        byte[] buf = new byte[BUFSIZE];
        DatagramSocket socket = new DatagramSocket(new InetSocketAddress(TFTPORT));

        log("INFO", "Listening at port " + TFTPORT + " for new requests");

        while (true) {

            InetSocketAddress clientAddress = receiveFrom(socket, buf);

            if (clientAddress == null) {
                continue;
            }

            log("INFO", "Received request from " + clientAddress.getPort());
            StringBuffer requestedFile = new StringBuffer();
            int opCode = parseRequest(buf, requestedFile);
            log("INFO", "Requested file: " + requestedFile.toString() + " :: opCode:  " + toOpCode(opCode));

            new Thread() {
                public void run() {
                    DatagramSocket sendSocket = checkTry(
                            "Address already in use.",
                            () -> new DatagramSocket(0));
                    checkTry(
                            "Failed connecting to socket.",
                            () -> sendSocket.connect(clientAddress));

                    if (sendSocket == null) {
                        return;
                    }

                    handleRequest(sendSocket, requestedFile.toString(), opCode);
                    sendSocket.close();
                }
            }.start();
        }

    }

    private InetSocketAddress receiveFrom(DatagramSocket socket, byte[] buf) {

        DatagramPacket packet = new DatagramPacket(buf, buf.length);
        checkTry("Error receiving packet.", () -> socket.receive(packet));
        return (InetSocketAddress) packet.getSocketAddress();

    }

    private int parseRequest(byte[] buf, StringBuffer requestedFile) {

        OpCode op = toOpCode(buf[1]);

        switch (op) {
            case Rrq, Wrq -> {
                int i = 2;
                while (buf[i] != 0) {
                    requestedFile.append((char) buf[i]);
                    i++;
                }
                return op.toInt();
            }
            default -> {
                return -1;
            }
        }

    }

    private void handleRequest(DatagramSocket socket, String requestedFile, int opCode) {

        OpCode op = toOpCode(opCode);

        switch (op) {
            case Rrq -> sendDataReceiveAck(READDIR + requestedFile, socket);
            case Wrq -> receiveAckSendData(WRITEDIR + requestedFile);
            default -> sendError(socket, 4, "Illegal TFTP operation.");
        }

    }

    private boolean sendDataReceiveAck(String requestedFile, DatagramSocket socket) {

        log("INFO", "Sending data.");

        byte[] packet = new byte[BUFSIZE];

        setMetaData(packet, 3, blockNumber);

        byte[] dataBuf = new byte[512];

        File file = new File(requestedFile);

        if (!file.exists()) {
            sendError(socket, 1, "File not found.");
            return false;
        }

        return true;
    }

    private boolean receiveAckSendData(String unknownParams) {

        return true;
    }

    private void sendError(DatagramSocket socket, int errCode, Error error) {

        byte[] packet = new byte[BUFSIZE];
        byte[] buf = error.getMsg().getBytes();

        setMetaData(packet, 5, errCode);

        for (int i = 0; i < buf.length; i++) {
            packet[i + 4] = buf[i];
        }

        checkTry("Error sending error reponse.", () -> socket.send(new DatagramPacket(packet, packet.length)));

        log("ERROR", error.getMsg());
    }

    private void setMetaData(byte[] packet, int opCode, int data) {

        packet[0] = 0;
        packet[1] = (byte) opCode;

        byte[] dataBytes = ByteBuffer.allocate(2).putShort((short) data).array();

        packet[2] = dataBytes[0];
        packet[3] = dataBytes[1];

    }

    private static void log(String level, String msg) {
        String date = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());

        String cross = "❌";
        String success = "✅";
        String warning = "⚠️️ ";
        String info = "#️⃣ ";

        switch (level) {
            case "ERROR" -> System.out.println(date + " :: " + cross + " :: " + msg);
            case "SUCCESS" -> System.out.println(date + " :: " + success + " :: " + msg);
            case "WARNING" -> System.out.println(date + " :: " + warning + " :: " + msg);
            case "INFO" -> System.out.println(date + " :: " + info + " :: " + msg);
            default -> System.out.println(date + " :: " + msg);
        }

    }

    private OpCode toOpCode(int opCode) {
        if (opCode < 1 || opCode > 4) {
            return OpCode.Err;
        }
        return OpCode.values()[opCode - 1];
    }

    private void checkTry(String errMsg, VoidThrow fn) {
        try {
            fn.run();
        } catch (Exception e) {
            log("ERROR", errMsg);
        }
    }

    private <T> T checkTry(String errMsg, Throwable<T> fn) {
        try {
            return fn.run();
        } catch (Exception e) {
            log("ERROR", errMsg);
        }
        return null;
    }

    @FunctionalInterface
    public interface Throwable<T> {
        T run() throws Exception;
    }

    public interface VoidThrow {
        void run() throws Exception;
    }
}