/*
 * This file is part of dependency-check-core.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) 2014 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Includes methods to generate the MD5 and SHA1 checksum.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
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
     * <p>
     * Creates the cryptographic checksum of a given file using the specified algorithm.</p>
     *
     * @param algorithm the algorithm to use to calculate the checksum
     * @param file the file to calculate the checksum for
     * @return the checksum
     * @throws IOException when the file does not exist
     * @throws NoSuchAlgorithmException when an algorithm is specified that does not exist
     */
    @SuppressWarnings("empty-statement")
    public static byte[] getChecksum(String algorithm, File file) throws NoSuchAlgorithmException, IOException {
        MessageDigest digest = MessageDigest.getInstance(algorithm);
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(file);
            FileChannel ch = fis.getChannel();
            MappedByteBuffer byteBuffer = ch.map(FileChannel.MapMode.READ_ONLY, 0, file.length());
            digest.update(byteBuffer);
//            BufferedInputStream bis = new BufferedInputStream(fis);
//            DigestInputStream dis = new DigestInputStream(bis, digest);
//            //yes, we are reading in a buffer for performance reasons - 1 byte at a time is SLOW
//            byte[] buffer = new byte[8192];
//            while (dis.read(buffer) != -1);
        } finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (IOException ex) {
                    LOGGER.log(Level.FINEST, "Error closing file '" + file.getName() + "'.", ex);
                }
            }
        }
        return digest.digest();
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
    /**
     * Hex code characters used in getHex.
     */
    private static final String HEXES = "0123456789ABCDEF";

    /**
     * <p>
     * Converts a byte array into a hex string.</p>
     *
     * <p>
     * This method was copied from <a
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
            hex.append(HEXES.charAt((b & 0xF0) >> 4)).append(HEXES.charAt(b & 0x0F));
        }
        return hex.toString();
    }
}
