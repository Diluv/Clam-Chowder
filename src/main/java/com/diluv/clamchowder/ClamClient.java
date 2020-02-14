package com.diluv.clamchowder;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * A client for interacting with ClamAV using socket commands.
 */
public class ClamClient {
    
    /**
     * The host name to connect to.
     */
    private final String host;
    
    /**
     * The port to connect to.
     */
    private final int port;
    
    /**
     * The timeout duration in milliseconds.
     */
    private final int timeout;
    
    /**
     * The byte size of the buffer used when scanning files. If you deal with large files
     * regularly and have the memory to spare, increasing this value
     */
    private final int scanChunkSize;
    
    /**
     * The byte size of the buffer used to read responses from the server. The average response
     * is extremely small so a smaller buffer size is fine.
     */
    private final int readBufferSize;
    
    /**
     * Creates a new ClamClient which can be used to interact with a ClamAV server. Keeping a
     * hard reference to the client is recommended as each request creates a new connection.
     * 
     * @param host The host name of the ClamAV server.
     */
    public ClamClient(String host) {
        
        this(host, Constants.DEFAULT_PORT);
    }
    
    /**
     * Creates a new ClamClient which can be used to interact with a ClamAV server. Keeping a
     * hard reference to the client is recommended as each request creates a new connection.
     * 
     * @param host The host name of the ClamAV server.
     * @param port The port the ClamAV server is running on.
     */
    public ClamClient(String host, int port) {
        
        this(host, port, Constants.DEFAULT_TIMEOUT);
    }
    
    /**
     * Creates a new ClamClient which can be used to interact with a ClamAV server. Keeping a
     * hard reference to the client is recommended as each request creates a new connection.
     * 
     * @param host The host name of the ClamAV server.
     * @param port The port the ClamAV server is running on.
     * @param timeout The amount of time in milliseconds to wait for responses.
     */
    public ClamClient(String host, int port, int timeout) {
        
        this(host, port, timeout, Constants.DEFAULT_SCAN_CHUNK_SIZE, Constants.DEFAULT_READ_BUFFER_SIZE);
    }
    
    /**
     * Creates a new ClamClient which can be used to interact with a ClamAV server. Keeping a
     * hard reference to the client is recommended as each request creates a new connection.
     * 
     * @param host The host name of the ClamAV server.
     * @param port The port the ClamAV server is running on.
     * @param timeout The amount of time in milliseconds to wait for responses.
     * @param scanChunkSize The buffer size to use when transferring scan data to ClamAV. Using
     *        a larger buffer can improve performance if the user has RAM to spare and the data
     *        being scanned is fairly big. The size of this buffer should not exceed the
     *        maximum chunk size configured in ClamAV. If you need a larger buffer you must
     *        configure ClamAV to allow larger chunks.
     * @param readBufferSize The buffer size to use when reading responses from ClamAV.
     *        Responses tend to be very small so this generally does not need to be very large.
     */
    public ClamClient(String host, int port, int timeout, int scanChunkSize, int readBufferSize) {
        
        this.host = host;
        this.port = port;
        this.timeout = timeout;
        
        this.scanChunkSize = scanChunkSize;
        this.readBufferSize = readBufferSize;
    }
    
    /**
     * Opens a new socket to the ClamAV server and initializes it with default properties.
     * 
     * @return The newly opened socket.
     */
    private Socket getSocket () throws IOException {
        
        final Socket socket = new Socket(this.host, this.port);
        socket.setSoTimeout(this.timeout);
        return socket;
    }
    
    /**
     * Sends a PING to the ClamAV server and awaits a response.
     * 
     * @return Whether or not the server responded with a valid PONG response.
     */
    public boolean ping () throws IOException {
        
        return this.sendCommand(Constants.CMD_PING, Constants.RSP_PONG);
    }
    
    /**
     * Sends a command to the ClamAV server and checks if the response matches an expected
     * result.
     * 
     * @param command The command to send. This is an ASCII string as a byte array.
     * @param expected The expected byte response from the server.
     * @return Whether or not the response matches the expected result.
     */
    public boolean sendCommand (byte[] command, byte[] expected) throws IOException {
        
        return Arrays.equals(expected, this.sendCommand(command));
    }
    
    /**
     * Sends a command to the ClamAV server.
     * 
     * @param command The command to send. This is an ASCII string as a byte array.
     * @return The response from the server as a byte array. Can be read as an ASCII string.
     */
    public byte[] sendCommand (byte[] command) throws IOException {
        
        try (Socket socket = this.getSocket(); OutputStream out = socket.getOutputStream()) {
            
            out.write(command);
            out.flush();
            
            return readAll(socket.getInputStream(), this.readBufferSize);
        }
    }
    
    /**
     * Scans a file using the ClamAV server and processes the results to a usable object.
     * 
     * @param file The file to scan.
     * @return The processed scan results.
     */
    public ScanResult scan (File file) throws IOException {
        
        final byte[] response = this.scanRaw(file);
        return new ScanResult(response);
    }
    
    /**
     * Scans a file using the ClamAV server and returns the raw response bytes.
     * 
     * @param file The file to scan.
     * @return The raw response bytes.
     */
    public byte[] scanRaw (File file) throws IOException {
        
        try (FileInputStream fileStream = new FileInputStream(file)) {
            
            return this.scanRaw(fileStream);
        }
    }
    
    /**
     * Scans an input stream using the ClamAV server and processes the results to a usable
     * object.
     * 
     * @param toScan The stream to scan.
     * @return The processed scan results.
     */
    public ScanResult scan (InputStream toScan) throws IOException {
        
        final byte[] response = this.scanRaw(toScan);
        return new ScanResult(response);
    }
    
    /**
     * Scans an input stream using the ClamAV server and returns the raw response bytes.
     * 
     * @param toScan The stream to scan.
     * @return The raw response bytes.
     */
    public byte[] scanRaw (InputStream toScan) throws IOException {
        
        try (Socket socket = this.getSocket(); OutputStream clamStream = new BufferedOutputStream(socket.getOutputStream())) {
            
            clamStream.write(Constants.CMD_INSTREAM);
            clamStream.flush();
            
            final byte[] buffer = new byte[this.scanChunkSize];
            
            try (InputStream clamInput = socket.getInputStream()) {
                
                // Read the first chunk of the input into the buffer.
                int nextChunkSize = toScan.read(buffer);
                
                while (nextChunkSize >= 0) {
                    
                    // Tell ClamAV the byte length of the chunk being sent.
                    clamStream.write(ByteBuffer.allocate(4).putInt(nextChunkSize).array());
                    
                    // Write the chunk from the buffer to ClamAV.
                    clamStream.write(buffer, 0, nextChunkSize);
                    
                    // Receiving a response prematurely means ClamAV aborted the scan.
                    if (clamInput.available() > 0) {
                        
                        throw new IOException("Scan aborted prematurely. Server says " + new String(readAll(clamInput, this.readBufferSize), StandardCharsets.US_ASCII));
                    }
                    
                    // Load the buffer with the next chunk.
                    nextChunkSize = toScan.read(buffer);
                }
                
                // Tell ClamAV that we are done and want to close the connection.
                clamStream.write(Constants.CMD_TERMINATE);
                clamStream.flush();
                
                // Read the scan results for the file.
                return readAll(clamInput, this.readBufferSize);
            }
        }
    }
    
    /**
     * Reads all the contents of an input stream to a new byte array.
     * 
     * @param toRead The stream to read from.
     * @param bufferLength The size of the buffer to use when reading.
     * @return A byte array containing all the contents of the input stream.
     */
    private static byte[] readAll (InputStream toRead, int bufferLength) throws IOException {
        
        final byte[] buffer = new byte[bufferLength];
        int readDepth;
        
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            
            while ((readDepth = toRead.read(buffer, 0, bufferLength)) != -1) {
                
                outputStream.write(buffer, 0, readDepth);
            }
            
            return outputStream.toByteArray();
        }
    }
}