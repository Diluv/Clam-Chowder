package com.diluv.clamchowder;

import java.nio.charset.StandardCharsets;

/**
 * This class holds references to constant values used by the ClamAV client.
 */
public class Constants {
    
    /**
     * The default ClamAV port value.
     */
    public static final int DEFAULT_PORT = 3310;
    
    /**
     * The default timeout for connections in milliseconds.
     */
    public static final int DEFAULT_TIMEOUT = 1000;
    
    /**
     * The default buffer size used when sending scan data to the server.
     */
    public static final int DEFAULT_SCAN_CHUNK_SIZE = 4096;
    
    /**
     * The default buffer size used when reading responses from the server. The default size is
     * very low due to the average response only being a couple bytes long.
     */
    public static final int DEFAULT_READ_BUFFER_SIZE = 128;
    
    /**
     * The encoded bytes for the PING command.
     */
    public static final byte[] CMD_PING = encode("PING", true);
    
    /**
     * The encoded bytes for the PONG response.
     */
    public static final byte[] RSP_PONG = encode("PONG", false);
    
    /**
     * The encoded bytes for the INSTREAM command.
     */
    public static final byte[] CMD_INSTREAM = encode("INSTREAM", true);
    
    /**
     * The encoded bytes for the UNKNOWN COMMAND response.
     */
    public static final byte[] RSP_UNKNOWN_COMMAND = encode("UNKNOWN COMMAND", false);
    
    /**
     * The encoded bytes for the terminate command.
     */
    public static final byte[] CMD_TERMINATE = new byte[] { 0, 0, 0, 0 };
    
    /**
     * Encodes a command into the expected ASCII format, and applies the proper null
     * termination formatting.
     * 
     * @param command The raw command to send. This should not have any termination formatting
     *        applied to it.
     * @param outgoing Whether the command is being sent (true) or received (false).
     * @return The command as an ASCII encoded byte array and null termination.
     */
    private static byte[] encode (String command, boolean outgoing) {
        
        final String toEncode = outgoing ? "z" + command + "\0" : command + "\0";
        return toEncode.getBytes(StandardCharsets.US_ASCII);
    }
}
