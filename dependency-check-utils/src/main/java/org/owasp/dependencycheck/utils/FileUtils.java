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
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A collection of utilities for processing information about files.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public final class FileUtils {

    /**
     * The logger.
     */
    private static final Logger LOGGER = Logger.getLogger(FileUtils.class.getName());
    /**
     * Bit bucket for non-Windows systems
     */
    private static final String BIT_BUCKET_UNIX = "/dev/null";

    /**
     * Bit bucket for Windows systems (yes, only one 'L')
     */
    private static final String BIT_BUCKET_WIN = "NUL";

    /**
     * Private constructor for a utility class.
     */
    private FileUtils() {
    }

    /**
     * Returns the (lowercase) file extension for a specified file.
     *
     * @param fileName the file name to retrieve the file extension from.
     * @return the file extension.
     */
    public static String getFileExtension(String fileName) {
        String ret = null;
        final int pos = fileName.lastIndexOf(".");
        if (pos >= 0) {
            ret = fileName.substring(pos + 1, fileName.length()).toLowerCase();
        }
        return ret;
    }

    /**
     * Deletes a file. If the File is a directory it will recursively delete the contents.
     *
     * @param file the File to delete
     * @return true if the file was deleted successfully, otherwise false
     */
    public static boolean delete(File file) {
        boolean success = true;
        if (!org.apache.commons.io.FileUtils.deleteQuietly(file)) {
            success = false;
            final String msg = String.format("Failed to delete file: %s; attempting to delete on exit.", file.getPath());
            LOGGER.log(Level.INFO, msg);
            file.deleteOnExit();
        }
        return success;
    }

    /**
     * Generates a new temporary file name that is guaranteed to be unique.
     *
     * @param prefix the prefix for the file name to generate
     * @param extension the extension of the generated file name
     * @return a temporary File
     * @throws java.io.IOException thrown if the temporary folder could not be created
     */
    public static File getTempFile(String prefix, String extension) throws IOException {
        final File dir = Settings.getTempDirectory();
        final String tempFileName = String.format("%s%s.%s", prefix, UUID.randomUUID().toString(), extension);
        final File tempFile = new File(dir, tempFileName);
        if (tempFile.exists()) {
            return getTempFile(prefix, extension);
        }
        return tempFile;
    }

    /**
     * Returns the data directory. If a path was specified in dependencycheck.properties or was specified using the
     * Settings object, and the path exists, that path will be returned as a File object. If it does not exist, then a
     * File object will be created based on the file location of the JAR containing the specified class.
     *
     * @param configuredFilePath the configured relative or absolute path
     * @param clazz the class to resolve the path
     * @return a File object
     * @throws IOException is thrown if the path could not be decoded
     * @deprecated This method should no longer be used. See the implementation in dependency-check-cli/App.java to see
     * how the data directory should be set.
     */
    @java.lang.Deprecated
    public static File getDataDirectory(String configuredFilePath, Class clazz) throws IOException {
        final File file = new File(configuredFilePath);
        if (file.isDirectory() && file.canWrite()) {
            return new File(file.getCanonicalPath());
        } else {
            final File exePath = getPathToJar(clazz);
            return new File(exePath, configuredFilePath);
        }
    }

    /**
     * Retrieves the physical path to the parent directory containing the provided class. For example, if a JAR file
     * contained a class org.something.clazz this method would return the parent directory of the JAR file.
     *
     * @param clazz the class to determine the parent directory of
     * @return the parent directory of the file containing the specified class.
     * @throws UnsupportedEncodingException thrown if UTF-8 is not supported.
     * @deprecated this should no longer be used.
     */
    @java.lang.Deprecated
    public static File getPathToJar(Class clazz) throws UnsupportedEncodingException {
        final String filePath = clazz.getProtectionDomain().getCodeSource().getLocation().getPath();
        final String decodedPath = URLDecoder.decode(filePath, "UTF-8");
        final File jarPath = new File(decodedPath);
        return jarPath.getParentFile();
    }

    /**
     * Return the bit bucket for the OS. '/dev/null' for Unix and 'NUL' for Windows
     *
     * @return a String containing the bit bucket
     */
    public static String getBitBucket() {
        if (System.getProperty("os.name").startsWith("Windows")) {
            return BIT_BUCKET_WIN;
        } else {
            return BIT_BUCKET_UNIX;
        }
    }
}
