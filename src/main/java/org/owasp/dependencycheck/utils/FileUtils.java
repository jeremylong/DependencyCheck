/*
 * This file is part of Dependency-Check.
 *
 * Dependency-Check is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Check is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Dependency-Check. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URLDecoder;

/**
 * A collection of utilities for processing information about files.
 *
 * @author Jeremy Long (jeremy.long@owasp.org)
 */
public final class FileUtils {

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
     * Deletes a file. If the File is a directory it will recursively delete
     * the contents.
     *
     * @param file the File to delete
     * @throws IOException is thrown if the file could not be deleted
     */
    public static void delete(File file) throws IOException {
        if (file.isDirectory()) {
            for (File c : file.listFiles()) {
                delete(c);
            }
        }
        if (!file.delete()) {
            throw new FileNotFoundException("Failed to delete file: " + file);
        }
    }

    /**
     * Returns the data directory. If a path was specified in dependencycheck.properties
     * or was specified using the Settings object, and the path exists, that path will be
     * returned as a File object. If it does not exist, then a File object will be created
     * based on the file location of the JAR containing the specified class.
     *
     * @param configuredFilePath the configured relative or absolute path
     * @param clazz the class whos path will be resolved
     * @return a File object
     * @throws IOException is thrown if the path could not be decoded
     */
    public static File getDataDirectory(String configuredFilePath, Class clazz) throws IOException {
        File file = new File(configuredFilePath);
        if (file.exists() && file.isDirectory() && file.canWrite()) {
            return file;
        } else {
            String filePath = clazz.getProtectionDomain().getCodeSource().getLocation().getPath();
            return new File(URLDecoder.decode(filePath, "UTF-8"));
        }
    }

}
