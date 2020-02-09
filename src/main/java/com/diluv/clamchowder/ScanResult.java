package com.diluv.clamchowder;

import java.nio.charset.StandardCharsets;

/**
 * Represents the processed version of a ClamAV scan result.
 */
public class ScanResult {
    
    /**
     * Regex pattern used to test if the response came back as ok.
     */
    private static final String RESPONSE_OK = "stream: OK";
    
    /**
     * Regex pattern used to test if the response has any malware found.
     */
    private static final String RESPONSE_FOUND = "stream: .+ FOUND";
    
    /**
     * Regex pattern used to test if the response is a size limit error.
     */
    private static final String RESPONSE_TOO_BIG = "INSTREAM size limit exceeded. ERROR";
    
    /**
     * The response message as an ASCII encoded string.
     */
    private final String response;
    
    /**
     * The status of the scanned data.
     */
    private final Status status;
    
    /**
     * The name of the malware pattern that was detected. Null if there was none.
     */
    private String found = null;
    
    /**
     * Processes a result from a raw byte response message. This constructor assumes the
     * response has not been tampered with and still has a terminator character.
     * 
     * @param response The raw response message.
     */
    public ScanResult(byte[] response) {
        
        this(new String(response, 0, response.length - 1, StandardCharsets.US_ASCII));
    }
    
    /**
     * Processes a result from an encoded response message.
     * 
     * @param response The response string to process. This must be in the appropriate format,
     *        and must not have a terminating character at the end.
     */
    public ScanResult(String response) {
        
        this.response = response;
        
        if (response.matches(RESPONSE_OK)) {
            
            this.status = Status.OK;
        }
        
        else if (response.matches(RESPONSE_FOUND)) {
            
            this.status = Status.FOUND;
            this.found = response.substring(8, response.length() - 6);
        }
        
        else if (response.matches(RESPONSE_TOO_BIG)) {
            
            this.status = Status.ERROR_TOO_BIG;
        }
        
        else {
            
            this.status = Status.UNKNOWN;
        }
    }
    
    /**
     * Gets the processed response as a string.
     * 
     * @return The response as a string.
     */
    public String getResponse () {
        
        return this.response;
    }
    
    /**
     * Gets the status for the scanned data.
     * 
     * @return The status of the scanned data.
     */
    public Status getStatus () {
        
        return this.status;
    }
    
    /**
     * Gets the name of the malware that was found. If null no malware was found.
     * 
     * @return The name of the malware. Null means nothing was found.
     */
    public String getFound () {
        
        return this.found;
    }
    
    /**
     * Enum containing all status cases currently handled.
     */
    public enum Status {
        
        /**
         * Scan completed successfully and no malware was found. File may not necessarily be
         * clean, but there were no matches.
         */
        OK,
        
        /**
         * Scan completed and a malware was found. One or more definitions matched.
         */
        FOUND,
        
        /**
         * The scan input was too big and was rejected by the server.
         */
        ERROR_TOO_BIG,
        
        /**
         * The scan completed but the response could not be understood. Potentially an unknown
         * error occurred.
         */
        UNKNOWN
    }
}