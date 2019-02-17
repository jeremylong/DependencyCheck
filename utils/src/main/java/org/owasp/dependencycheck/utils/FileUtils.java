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

import java.io.Closeable;
import org.apache.commons.io.FilenameUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.UUID;
import org.apache.commons.lang3.SystemUtils;

/**
 * A collection of utilities for processing information about files.
 *
 * @author Jeremy Long
 * @version $Id: $Id
 */
public final class FileUtils {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(FileUtils.class);
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
        final String fileExt = FilenameUtils.getExtension(fileName);
        return null == fileExt || fileExt.isEmpty() ? null : fileExt.toLowerCase();
    }

    /**
     * Deletes a file. If the File is a directory it will recursively delete the
     * contents.
     *
     * @param file the File to delete
     * @return true if the file was deleted successfully, otherwise false
     */
    public static boolean delete(File file) {
        final boolean success = org.apache.commons.io.FileUtils.deleteQuietly(file);
        if (!success) {
            LOGGER.debug("Failed to delete file: {}; attempting to delete on exit.", file.getPath());
            file.deleteOnExit();
        }
        return success;
    }

    /**
     * Creates a unique temporary directory in the given directory.
     *
     * @param base the base directory to create a temporary directory within
     * @return the temporary directory
     * @throws java.io.IOException thrown when a directory cannot be created within the
     * base directory
     */
    public static File createTempDirectory(File base) throws IOException {
        final File tempDir = new File(base, "dctemp" + UUID.randomUUID().toString());
        if (tempDir.exists()) {
            return createTempDirectory(base);
        }
        if (!tempDir.mkdirs()) {
            throw new IOException("Could not create temp directory `" + tempDir.getAbsolutePath() + "`");
        }
        LOGGER.debug("Temporary directory is `{}`", tempDir.getAbsolutePath());
        return tempDir;
    }

    /**
     * Return the bit bucket for the OS. '/dev/null' for Unix and 'NUL' for
     * Windows
     *
     * @return a String containing the bit bucket
     */
    public static String getBitBucket() {
        if (SystemUtils.IS_OS_WINDOWS) {
            return BIT_BUCKET_WIN;
        } else {
            return BIT_BUCKET_UNIX;
        }
    }

    /**
     * Close the given {@link java.io.Closeable} instance, ignoring nulls, and logging
     * any thrown {@link java.io.IOException}.
     *
     * @param closeable to be closed
     */
    public static void close(Closeable closeable) {
        if (null != closeable) {
            try {
                closeable.close();
            } catch (IOException ex) {
                LOGGER.trace("", ex);
            }
        }
    }

    /**
     * Gets the {@link java.io.InputStream} for this resource.
     *
     * @param resource path
     * @return the input stream for the given resource
     */
    public static InputStream getResourceAsStream(String resource) {
        return FileUtils.class.getClassLoader() != null
                ? FileUtils.class.getClassLoader().getResourceAsStream(resource)
                : ClassLoader.getSystemResourceAsStream(resource);
    }
}
