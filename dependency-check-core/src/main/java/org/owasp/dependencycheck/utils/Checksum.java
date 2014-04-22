package org.owasp.dependencycheck.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Includes methods to generate the MD5 and SHA1 checksum.
 *
 * This code was copied from Real's How To. It has been slightly modified.
 *
 * Written and compiled by Réal Gagnon ©1998-2012
 *
 * @author Real's How To: http://www.rgagnon.com/javadetails/java-0416.html
 *
 */
public final class Checksum {
    
    /**
     * The logger.
     */
    private static final Logger LOGGER = Logger.getLogger(Checksum.class.getName());
    /**
     * Private constructor for a utility class.
     */
    private Checksum() {
    }

    /**
     * <p>Creates the cryptographic checksum of a given file using the specified
     * algorithm.</p> <p>This algorithm was copied and heavily modified from
     * Real's How To: http://www.rgagnon.com/javadetails/java-0416.html</p>
     *
     * @param algorithm the algorithm to use to calculate the checksum
     * @param file the file to calculate the checksum for
     * @return the checksum
     * @throws IOException when the file does not exist
     * @throws NoSuchAlgorithmException when an algorithm is specified that does
     * not exist
     */
    public static byte[] getChecksum(String algorithm, File file) throws NoSuchAlgorithmException, IOException {
        InputStream fis = null;
        byte[] buffer = new byte[1024];
        MessageDigest complete = MessageDigest.getInstance(algorithm);
        int numRead;
        try {
            fis = new FileInputStream(file);
            do {
                numRead = fis.read(buffer);
                if (numRead > 0) {
                    complete.update(buffer, 0, numRead);
                }
            } while (numRead != -1);
        } finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (IOException ex) {
                    LOGGER.log(Level.FINEST, "Error closing file '" + file.getName() + "'.", ex);
                }
            }
        }
        return complete.digest();
    }

    /**
     * Calculates the MD5 checksum of a specified file.
     *
     * @param file the file to generate the MD5 checksum
     * @return the hex representation of the MD5 hash
     * @throws IOException when the file passed in does not exist
     * @throws NoSuchAlgorithmException when the MD5 algorithm is not available
     */
    public static String getMD5Checksum(File file) throws IOException, NoSuchAlgorithmException {
        byte[] b = getChecksum("MD5", file);
        return getHex(b);
    }

    /**
     * Calculates the SHA1 checksum of a specified file.
     *
     * @param file the file to generate the MD5 checksum
     * @return the hex representation of the SHA1 hash
     * @throws IOException when the file passed in does not exist
     * @throws NoSuchAlgorithmException when the SHA1 algorithm is not available
     */
    public static String getSHA1Checksum(File file) throws IOException, NoSuchAlgorithmException {
        byte[] b = getChecksum("SHA1", file);
        return getHex(b);
    }
    private static final String HEXES = "0123456789ABCDEF";

    /**
     * <p>Converts a byte array into a hex string.</p>
     *
     * <p>This method was copied from <a
     * href="http://www.rgagnon.com/javadetails/java-0596.html">http://www.rgagnon.com/javadetails/java-0596.html</a></p>
     *
     * @param raw a byte array
     * @return the hex representation of the byte array
     */
    public static String getHex(byte[] raw) {
        if (raw == null) {
            return null;
        }
        final StringBuilder hex = new StringBuilder(2 * raw.length);
        for (final byte b : raw) {
            hex.append(HEXES.charAt((b & 0xF0) >> 4)).append(HEXES.charAt((b & 0x0F)));
        }
        return hex.toString();
    }
}
