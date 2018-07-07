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
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.charset.UnsupportedCharsetException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Includes methods to generate the MD5 and SHA1 checksum.
 *
 * @author Jeremy Long
 *
 */
public final class Checksum {

    /**
     * Hex code characters used in getHex.
     */
    private static final String HEXES = "0123456789abcdef";

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(Checksum.class);
    /**
     * MD5 constant.
     */
    private static final String MD5 = "MD5";
    /**
     * SHA1 constant.
     */
    private static final String SHA1 = "SHA1";
    /**
     * SHA256 constant.
     */
    private static final String SHA256 = "SHA-256";

    /**
     * Private constructor for a utility class.
     */
    private Checksum() {
    }

    /**
     * <p>
     * Creates the cryptographic checksum of a given file using the specified
     * algorithm.</p>
     *
     * @param algorithm the algorithm to use to calculate the checksum
     * @param file the file to calculate the checksum for
     * @return the checksum
     * @throws IOException when the file does not exist
     * @throws NoSuchAlgorithmException when an algorithm is specified that does
     * not exist
     */
    public static byte[] getChecksum(String algorithm, File file) throws NoSuchAlgorithmException, IOException {
        final MessageDigest md = MessageDigest.getInstance(algorithm);
        try (FileInputStream fis = new FileInputStream(file);
                FileChannel ch = fis.getChannel()) {
            final ByteBuffer buf = ByteBuffer.allocateDirect(8192);
            int b = ch.read(buf);
            while (b != -1 && b != 0) {
                buf.flip();
                final byte[] bytes = new byte[b];
                buf.get(bytes);
                md.update(bytes, 0, b);
                buf.clear();
                b = ch.read(buf);
            }
            return md.digest();
        }
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
        final byte[] b = getChecksum(MD5, file);
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
        final byte[] b = getChecksum(SHA1, file);
        return getHex(b);
    }

    /**
     * Calculates the SH256 checksum of a specified file.
     *
     * @param file the file to generate the MD5 checksum
     * @return the hex representation of the SHA1 hash
     * @throws IOException when the file passed in does not exist
     * @throws NoSuchAlgorithmException when the SHA1 algorithm is not available
     */
    public static String getSHA256Checksum(File file) throws IOException, NoSuchAlgorithmException {
        final byte[] b = getChecksum(SHA256, file);
        return getHex(b);
    }

    /**
     * Calculates the MD5 checksum of a specified bytes.
     *
     * @param algorithm the algorithm to use (md5, sha1, etc.) to calculate the
     * message digest
     * @param bytes the bytes to generate the MD5 checksum
     * @return the hex representation of the MD5 hash
     */
    public static String getChecksum(String algorithm, byte[] bytes) {
        final MessageDigest digest = getMessageDigest(algorithm);
        final byte[] b = digest.digest(bytes);
        return getHex(b);
    }

    /**
     * Calculates the MD5 checksum of the specified text.
     *
     * @param text the text to generate the MD5 checksum
     * @return the hex representation of the MD5
     */
    public static String getMD5Checksum(String text) {
        final byte[] data = stringToBytes(text);
        return getChecksum(MD5, data);
    }

    /**
     * Calculates the SHA1 checksum of the specified text.
     *
     * @param text the text to generate the SHA1 checksum
     * @return the hex representation of the SHA1
     */
    public static String getSHA1Checksum(String text) {
        final byte[] data = stringToBytes(text);
        return getChecksum(SHA1, data);
    }

    /**
     * Calculates the SHA1 checksum of the specified text.
     *
     * @param text the text to generate the SHA1 checksum
     * @return the hex representation of the SHA1
     */
    public static String getSHA256Checksum(String text) {
        final byte[] data = stringToBytes(text);
        return getChecksum(SHA256, data);
    }

    /**
     * Converts the given text into bytes.
     *
     * @param text the text to convert
     * @return the bytes
     */
    private static byte[] stringToBytes(String text) {
        byte[] data;
        try {
            data = text.getBytes(Charset.forName(StandardCharsets.UTF_8.name()));
        } catch (UnsupportedCharsetException ex) {
            data = text.getBytes(Charset.defaultCharset());
        }
        return data;
    }

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

    /**
     * Returns the message digest.
     *
     * @param algorithm the algorithm for the message digest
     * @return the message digest
     */
    private static MessageDigest getMessageDigest(String algorithm) {
        try {
            return MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error(e.getMessage());
            final String msg = String.format("Failed to obtain the %s message digest.", algorithm);
            throw new IllegalStateException(msg, e);
        }
    }
}
