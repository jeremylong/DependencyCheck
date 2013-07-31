/*
 * This file is part of dependency-check-core.
 *
 * Dependency-check-core is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-check-core is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * dependency-check-core. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
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
     * Deletes a file. If the File is a directory it will recursively delete the
     * contents.
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
     * Returns the data directory. If a path was specified in
     * dependencycheck.properties or was specified using the Settings object,
     * and the path exists, that path will be returned as a File object. If it
     * does not exist, then a File object will be created based on the file
     * location of the JAR containing the specified class.
     *
     * @param configuredFilePath the configured relative or absolute path
     * @param clazz the class whos path will be resolved
     * @return a File object
     * @throws IOException is thrown if the path could not be decoded
     * @deprecated This method should no longer be used. See the implementation
     * in dependency-check-cli/App.java to see how the data directory should be
     * set.
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
     * Retrieves the physical path to the parent directory containing the
     * provided class. For example, if a JAR file contained a class
     * org.something.clazz this method would return the parent directory of the
     * JAR file.
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
}
