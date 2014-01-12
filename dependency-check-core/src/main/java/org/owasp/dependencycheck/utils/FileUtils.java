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

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import org.owasp.dependencycheck.Engine;

/**
 * A collection of utilities for processing information about files.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public final class FileUtils {

    /**
     * The buffer size to use when extracting files from the archive.
     */
    private static final int BUFFER_SIZE = 4096;

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
        if (!org.apache.commons.io.FileUtils.deleteQuietly(file)) {
            throw new FileNotFoundException("Failed to delete file: " + file);
        }
        /* else {
         //delete on exit was a bad idea. if for some reason the file can't be deleted
         // this will cause a newly constructed file to be deleted and a subsequent run may fail.
         // still not sure why a file fails to be deleted, but can be overwritten... odd.
         file.deleteOnExit();
         }*/
    }

    /**
     * Returns the data directory. If a path was specified in
     * dependencycheck.properties or was specified using the Settings object,
     * and the path exists, that path will be returned as a File object. If it
     * does not exist, then a File object will be created based on the file
     * location of the JAR containing the specified class.
     *
     * @param configuredFilePath the configured relative or absolute path
     * @param clazz the class to resolve the path
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

    /**
     * Extracts the contents of an archive into the specified directory.
     *
     * @param archive an archive file such as a WAR or EAR
     * @param extractTo a directory to extract the contents to
     * @throws ExtractionException thrown if an exception occurs while
     * extracting the files
     */
    public static void extractFiles(File archive, File extractTo) throws ExtractionException {
        extractFiles(archive, extractTo, null);
    }

    /**
     * Extracts the contents of an archive into the specified directory. The
     * files are only extracted if they are supported by the analyzers loaded
     * into the specified engine. If the engine is specified as null then all
     * files are extracted.
     *
     * @param archive an archive file such as a WAR or EAR
     * @param extractTo a directory to extract the contents to
     * @param engine the scanning engine
     * @throws ExtractionException thrown if there is an error extracting the
     * files
     */
    public static void extractFiles(File archive, File extractTo, Engine engine) throws ExtractionException {
        if (archive == null || extractTo == null) {
            return;
        }

        FileInputStream fis = null;
        ZipInputStream zis = null;

        try {
            fis = new FileInputStream(archive);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(FileUtils.class.getName()).log(Level.INFO, null, ex);
            throw new ExtractionException("Archive file was not found.", ex);
        }
        zis = new ZipInputStream(new BufferedInputStream(fis));
        ZipEntry entry;
        try {
            while ((entry = zis.getNextEntry()) != null) {
                if (entry.isDirectory()) {
                    final File d = new File(extractTo, entry.getName());
                    if (!d.exists() && !d.mkdirs()) {
                        final String msg = String.format("Unable to create '%s'.", d.getAbsolutePath());
                        throw new ExtractionException(msg);
                    }
                } else {
                    final File file = new File(extractTo, entry.getName());
                    final String ext = getFileExtension(file.getName());
                    if (engine == null || engine.supportsExtension(ext)) {
                        BufferedOutputStream bos = null;
                        FileOutputStream fos;
                        try {
                            fos = new FileOutputStream(file);
                            bos = new BufferedOutputStream(fos, BUFFER_SIZE);
                            int count;
                            final byte data[] = new byte[BUFFER_SIZE];
                            while ((count = zis.read(data, 0, BUFFER_SIZE)) != -1) {
                                bos.write(data, 0, count);
                            }
                            bos.flush();
                        } catch (FileNotFoundException ex) {
                            Logger.getLogger(FileUtils.class.getName()).log(Level.FINE, null, ex);
                            final String msg = String.format("Unable to find file '%s'.", file.getName());
                            throw new ExtractionException(msg, ex);
                        } catch (IOException ex) {
                            Logger.getLogger(FileUtils.class.getName()).log(Level.FINE, null, ex);
                            final String msg = String.format("IO Exception while parsing file '%s'.", file.getName());
                            throw new ExtractionException(msg, ex);
                        } finally {
                            if (bos != null) {
                                try {
                                    bos.close();
                                } catch (IOException ex) {
                                    Logger.getLogger(FileUtils.class.getName()).log(Level.FINEST, null, ex);
                                }
                            }
                        }
                    }
                }
            }
        } catch (IOException ex) {
            final String msg = String.format("Exception reading archive '%s'.", archive.getName());
            Logger.getLogger(FileUtils.class.getName()).log(Level.FINE, msg, ex);
            throw new ExtractionException(msg, ex);
        } finally {
            try {
                zis.close();
            } catch (IOException ex) {
                Logger.getLogger(FileUtils.class.getName()).log(Level.FINEST, null, ex);
            }
        }
    }
}
