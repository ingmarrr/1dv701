import java.net.DatagramSocket;
import java.net.DatagramPacket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.util.Arrays;
import java.util.Date;
import java.text.SimpleDateFormat;
import java.io.File;
import java.nio.ByteBuffer;
import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileNotFoundException;
import java.io.ByteArrayOutputStream;
import java.nio.file.Files;

public class App {
    private static final int TFTPORT = 4970;
    private static final int PACKETSIZE = 516;
    private static final int BUFSIZE = 512;
    private static final String READDIR = "/Users/ingmarfalk/uni/ComputerNetworks_1DV701/a3/read/";
    private static final String WRITEDIR = "/Users/ingmarfalk/uni/ComputerNetworks_1DV701/a3/write/";
    // private int blockNumber = 1;
    private static int clientTID;
    private static int serverTID;

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
        MissingSpace("Disk full or allocation exceeded."),
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

        log("LINE", "Starting server...");
        checkTry("Failed to start Application", () -> {
            App server = new App();
            server.start();
        });
    }

    private void start() throws SocketException {

        byte[] packetBuf = new byte[PACKETSIZE];
        DatagramSocket socket = new DatagramSocket(new InetSocketAddress(TFTPORT));

        // log("INFO", "Listening at port " + TFTPORT + " for new requests");
        log("LINE", "Listening at port " + TFTPORT + " for new requests.");

        while (true) {

            InetSocketAddress clientAddress = receiveFrom(socket, packetBuf);

            if (clientAddress == null) {
                continue;
            }

            // log("INFO", "Received request from " + clientAddress.getPort());
            log("LINE", "Received request from " + clientAddress.getPort());
            StringBuffer requestedFile = new StringBuffer();
            int opCode = parseRequest(packetBuf, requestedFile);
            // log("INFO", "Requested file: " + requestedFile.toString() + " :: opCode: " +
            // toOpCode(opCode));
            log("LINE", "Requested file: " + requestedFile.toString() + " :: opCode:  " + toOpCode(opCode));

            new Thread() {
                public void run() {
                    DatagramSocket sendSocket = checkTry(
                            "Address already in use.",
                            () -> new DatagramSocket(0));
                    checkTry(
                            "Failed connecting to socket.",
                            () -> sendSocket.connect(clientAddress));
                    clientTID = socket.getPort();
                    serverTID = socket.getLocalPort();

                    if (sendSocket == null) {
                        return;
                    }

                    handleRequest(sendSocket, requestedFile.toString(), opCode);
                    sendSocket.close();
                }
            }.start();
        }

    }

    private InetSocketAddress receiveFrom(DatagramSocket socket, byte[] packetBuf) {

        DatagramPacket packet = new DatagramPacket(packetBuf, packetBuf.length);
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
            case Wrq -> receiveDataSendAck(WRITEDIR + requestedFile, socket);
            default -> sendError(socket, Error.IllegalTFTPOperation);
        }

    }

    private boolean sendDataReceiveAck(String requestedFile, DatagramSocket socket) {

        log("LINE", "Sending data.");

        File file = new File(requestedFile);
        int block = 1;

        log("LINE", requestedFile);

        if (!file.exists()) {
            sendError(socket, Error.FileNotFound);
            return false;
        }

        FileInputStream fis = checkTry(file.getName() + " not found.", () -> new FileInputStream(file));

        while (true) {
            byte[] buf = new byte[BUFSIZE];
            int bytesRead = checkIOTry(socket, Error.AccessViolation, () -> fis.read(buf));
            byte[] data = setBytes(buf, 3, block);

            int sendCnt = 0;

            checkTry("Could not set socket timeout.", () -> socket.setSoTimeout(5000));

            send: while (sendCnt < 5) {
                sendCnt++;
                DatagramPacket packet = new DatagramPacket(data, bytesRead + 4);
                checkTry("Error sending packet.", () -> socket.send(packet));
                log("SUCCESS", "Sent block (" + block + ")");

                ByteBuffer ack = ByteBuffer.allocate(4);
                byte[] ackBytes = ack.array();
                DatagramPacket ackPacket = new DatagramPacket(ackBytes, ackBytes.length);
                checkTry("Error receiving acknowledgement packet from socket.", () -> socket.receive(ackPacket));
                log("SUCCESS", "Received acknowledgement packet.");

                OpCode opCode = toOpCode(ack.getShort());
                short blockOrError = ack.getShort();

                if (opCode == OpCode.Ack && blockOrError == block) {
                    break send;
                }

                if (opCode == OpCode.Err) {
                    Error error = Error.values()[blockOrError - 1];
                    sendError(socket, error);
                    return false;
                }

                if (clientTID != socket.getPort() && serverTID != socket.getLocalPort()) {
                    sendError(socket, Error.UnknownTID);
                    return false;
                }
            }

            if (sendCnt >= 5) {
                sendError(socket, Error.UnknownTID);
                return false;
            }

            if (bytesRead < BUFSIZE) {
                break;
            }

            block++;
        }

        log("SUCCESS", "Sent file.");
        checkTry("Error closing file input stream.", () -> fis.close());
        return true;
    }

    private boolean receiveDataSendAck(String requestedFile, DatagramSocket socket) {

        log("LINE", "Receiving data.");

        File file = new File(requestedFile);
        int block = 0;

        if (file.exists()) {
            sendError(socket, Error.FileAlreadyExists);
            return false;
        }

        FileOutputStream out = checkIOTry(socket, Error.AccessViolation, () -> new FileOutputStream(requestedFile));
        ByteBuffer ack = setBytes(4, 4, block);
        byte[] ackBytes = ack.array();
        DatagramPacket ackPacket = new DatagramPacket(ackBytes, ackBytes.length);
        checkTry("Error sending acknowledgement packet.", () -> socket.send(ackPacket));

        receiveLoop: while (true) {
            checkTry("Could not set socket timeout.", () -> socket.setSoTimeout(5000));

            byte[] buf = new byte[PACKETSIZE];
            DatagramPacket packet = new DatagramPacket(buf, buf.length);
            checkTry("Error receiving packet from socket.", () -> socket.receive(packet));
            log("SUCCESS", "Received data packet.");

            ByteBuffer wrapped = ByteBuffer.wrap(packet.getData());
            OpCode opCode = toOpCode(wrapped.getShort());

            switch (opCode) {
                case Data -> {
                    byte[] data = Arrays.copyOfRange(packet.getData(), 4, packet.getLength());
                    long freeSpace = new File(WRITEDIR).getUsableSpace();
                    if (data.length > freeSpace) {
                        sendError(socket, Error.MissingSpace);
                        return false;
                    }
                    checkTry("Error writing received data to file.", () -> {
                        out.write(data);
                        out.flush();
                        log("SUCCESS", "Wrote " + requestedFile + " into " + WRITEDIR);
                    });

                    ByteBuffer ackData = setBytes(4, 4, wrapped.getShort());
                    byte[] ackDataBytes = ackData.array();
                    DatagramPacket ackDataPacket = new DatagramPacket(ackDataBytes, ackDataBytes.length);
                    checkTry("Error sending acknowledgement packet to socket.", () -> socket.send(ackDataPacket));
                    log("SUCCESS", "Sent acknowledgement packet.");

                    if (data.length < BUFSIZE) {
                        socket.close();
                        checkTry("Error closing file output stream.", () -> out.close());
                        log("LINE", "Closed socket and output stream.");
                        break receiveLoop;
                    }
                }
                case Err -> {
                    Error error = Error.values()[wrapped.getShort()];
                    sendError(socket, error);
                    return false;
                }
                default -> {
                    sendError(socket, Error.IllegalTFTPOperation);
                    return false;
                }
            }
        }

        return true;
    }

    private void sendError(DatagramSocket socket, Error error) {

        byte[] packet = setBytes(error.getMsg().getBytes(), 5, error.ordinal());
        checkTry("Error sending error reponse.", () -> socket.send(new DatagramPacket(packet, packet.length)));
        log("ERROR", error.getMsg());
    }

    private ByteBuffer setBytes(int size, int opCode, int info) {
        ByteBuffer bb = ByteBuffer.allocate(size);
        bb.putShort((short) opCode);
        bb.putShort((short) info);

        return bb;
    }

    private byte[] setBytes(byte[] bytes, int opCode, int info) {
        ByteBuffer bb = ByteBuffer.allocate(bytes.length + 4);
        bb.putShort((short) opCode);
        bb.putShort((short) info);
        bb.put(bytes);
        return bb.array();
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
            case "LINE" -> {
                int lineNumber = Thread.currentThread().getStackTrace()[2].getLineNumber();
                System.out.println(date + " :: " + lineNumber + " :: " + msg);
            }
            default -> System.out.println(date + " :: " + msg);
        }
    }

    private static void logMsg(String errMsg) {
        String fullClassName = Thread.currentThread().getStackTrace()[2].getClassName();
        String className = fullClassName.substring(fullClassName.lastIndexOf(".") + 1);
        String methodName = Thread.currentThread().getStackTrace()[2].getMethodName();
        int lineNumber = Thread.currentThread().getStackTrace()[2].getLineNumber();

        System.out.println(className + "." + methodName + "():" + lineNumber + "\t:: " + errMsg);
    }

    private OpCode toOpCode(int opCode) {
        if (opCode < 1 || opCode > 4) {
            return OpCode.Err;
        }
        return OpCode.values()[opCode - 1];
    }

    private static void checkTry(String errMsg, VoidThrow fn) {
        try {
            fn.run();
        } catch (SocketException e) {
            log("ERROR", "SocketException :: " + errMsg);
        } catch (IOException e) {
            log("ERROR", "IOException :: " + errMsg);
        } catch (Exception e) {
            log("ERROR", errMsg);
        }
    }

    private static <T> T checkTry(String errMsg, Throwable<T> fn) {
        try {
            return fn.run();
        } catch (SocketException e) {
            log("ERROR", "SocketException :: " + errMsg);
        } catch (IOException e) {
            log("ERROR", "IOException :: " + errMsg);
        } catch (Exception e) {
            log("ERROR", errMsg);
        }
        return null;
    }

    private <T> T checkIOTry(DatagramSocket socket, Error error, Throwable<T> fn) {
        try {
            return fn.run();
        } catch (IOException e) {
            sendError(socket, Error.FileNotFound);
            log("ERROR", "IOException :: " + error.getMsg());
        } catch (Exception e) {
            log("ERROR", error.getMsg());
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
