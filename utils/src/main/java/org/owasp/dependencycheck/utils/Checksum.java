/*
 * This file is part of dependency-check-utils.
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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Includes methods to generate the MD5 and SHA1 checksum.
 *
 * @author Jeremy Long
 * @version $Id: $Id
 */
public final class Checksum {

    /**
     * Hex code characters used in getHex.
     */
    private static final String HEXES = "0123456789abcdef";
    /**
     * Buffer size for calculating checksums.
     */
    private static final int BUFFER_SIZE = 1024;

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
    private static final String SHA1 = "SHA-1";
    /**
     * SHA256 constant.
     */
    private static final String SHA256 = "SHA-256";
    /**
     * Cached file checksums for each supported algorithm.
     */
    private static final Map<File, FileChecksums> CHECKSUM_CACHE = new ConcurrentHashMap<>();

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
     * @throws java.io.IOException when the file does not exist
     * @throws java.security.NoSuchAlgorithmException when an algorithm is
     * specified that does not exist
     */
    public static String getChecksum(String algorithm, File file) throws NoSuchAlgorithmException, IOException {
        FileChecksums fileChecksums = CHECKSUM_CACHE.get(file);
        if (fileChecksums == null) {
            try (InputStream stream = Files.newInputStream(file.toPath())) {
                final MessageDigest md5Digest = getMessageDigest(MD5);
                final MessageDigest sha1Digest = getMessageDigest(SHA1);
                final MessageDigest sha256Digest = getMessageDigest(SHA256);
                final byte[] buffer = new byte[BUFFER_SIZE];
                int read = stream.read(buffer, 0, BUFFER_SIZE);
                while (read > -1) {
                    // update all checksums together instead of reading the file multiple times
                    md5Digest.update(buffer, 0, read);
                    sha1Digest.update(buffer, 0, read);
                    sha256Digest.update(buffer, 0, read);
                    read = stream.read(buffer, 0, BUFFER_SIZE);
                }
                fileChecksums = new FileChecksums(
                        getHex(md5Digest.digest()),
                        getHex(sha1Digest.digest()),
                        getHex(sha256Digest.digest())
                );
                CHECKSUM_CACHE.put(file, fileChecksums);
            }
        }
        switch (algorithm.toUpperCase()) {
            case MD5:
                return fileChecksums.md5;
            case SHA1:
                return fileChecksums.sha1;
            case SHA256:
                return fileChecksums.sha256;
            default:
                throw new NoSuchAlgorithmException(algorithm);
        }
    }

    /**
     * Calculates the MD5 checksum of a specified file.
     *
     * @param file the file to generate the MD5 checksum
     * @return the hex representation of the MD5 hash
     * @throws java.io.IOException when the file passed in does not exist
     * @throws java.security.NoSuchAlgorithmException when the MD5 algorithm is
     * not available
     */
    public static String getMD5Checksum(File file) throws IOException, NoSuchAlgorithmException {
        return getChecksum(MD5, file);
    }

    /**
     * Calculates the SHA1 checksum of a specified file.
     *
     * @param file the file to generate the MD5 checksum
     * @return the hex representation of the SHA1 hash
     * @throws java.io.IOException when the file passed in does not exist
     * @throws java.security.NoSuchAlgorithmException when the SHA1 algorithm is
     * not available
     */
    public static String getSHA1Checksum(File file) throws IOException, NoSuchAlgorithmException {
        return getChecksum(SHA1, file);
    }

    /**
     * Calculates the SH256 checksum of a specified file.
     *
     * @param file the file to generate the MD5 checksum
     * @return the hex representation of the SHA1 hash
     * @throws java.io.IOException when the file passed in does not exist
     * @throws java.security.NoSuchAlgorithmException when the SHA1 algorithm is
     * not available
     */
    public static String getSHA256Checksum(File file) throws IOException, NoSuchAlgorithmException {
        return getChecksum(SHA256, file);
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
        return getHex(getMessageDigest(algorithm).digest(bytes));
    }

    /**
     * Calculates the MD5 checksum of the specified text.
     *
     * @param text the text to generate the MD5 checksum
     * @return the hex representation of the MD5
     */
    public static String getMD5Checksum(String text) {
        return getChecksum(MD5, stringToBytes(text));
    }

    /**
     * Calculates the SHA1 checksum of the specified text.
     *
     * @param text the text to generate the SHA1 checksum
     * @return the hex representation of the SHA1
     */
    public static String getSHA1Checksum(String text) {
        return getChecksum(SHA1, stringToBytes(text));
    }

    /**
     * Calculates the SHA256 checksum of the specified text.
     *
     * @param text the text to generate the SHA1 checksum
     * @return the hex representation of the SHA1
     */
    public static String getSHA256Checksum(String text) {
        return getChecksum(SHA256, stringToBytes(text));
    }

    /**
     * Converts the given text into bytes.
     *
     * @param text the text to convert
     * @return the bytes
     */
    private static byte[] stringToBytes(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
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
            LOGGER.error(e.getMessage(), e);
            final String msg = String.format("Failed to obtain the %s message digest.", algorithm);
            throw new IllegalStateException(msg, e);
        }
    }

    /**
     * File checksums for each supported algorithm
     */
    private static class FileChecksums {

        /**
         * MD5.
         */
        private final String md5;
        /**
         * SHA1.
         */
        private final String sha1;
        /**
         * SHA256.
         */
        private final String sha256;

        FileChecksums(String md5, String sha1, String sha256) {
            this.md5 = md5;
            this.sha1 = sha1;
            this.sha256 = sha256;
        }
    }
}
