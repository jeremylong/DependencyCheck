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
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import org.owasp.dependencycheck.Engine;
import static org.owasp.dependencycheck.utils.FileUtils.getFileExtension;

/**
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public final class ExtractionUtil {

    /**
     * The logger.
     */
    private static final Logger LOGGER = Logger.getLogger(ExtractionUtil.class.getName());
    /**
     * The buffer size to use when extracting files from the archive.
     */
    private static final int BUFFER_SIZE = 4096;

    /**
     * Private constructor for a utility class.
     */
    private ExtractionUtil() {
    }

    /**
     * Extracts the contents of an archive into the specified directory.
     *
     * @param archive an archive file such as a WAR or EAR
     * @param extractTo a directory to extract the contents to
     * @throws ExtractionException thrown if an exception occurs while extracting the files
     */
    public static void extractFiles(File archive, File extractTo) throws ExtractionException {
        extractFiles(archive, extractTo, null);
    }

    /**
     * Extracts the contents of an archive into the specified directory. The files are only extracted if they are
     * supported by the analyzers loaded into the specified engine. If the engine is specified as null then all files
     * are extracted.
     *
     * @param archive an archive file such as a WAR or EAR
     * @param extractTo a directory to extract the contents to
     * @param engine the scanning engine
     * @throws ExtractionException thrown if there is an error extracting the files
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
            LOGGER.log(Level.FINE, null, ex);
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
                            LOGGER.log(Level.FINE, null, ex);
                            final String msg = String.format("Unable to find file '%s'.", file.getName());
                            throw new ExtractionException(msg, ex);
                        } catch (IOException ex) {
                            LOGGER.log(Level.FINE, null, ex);
                            final String msg = String.format("IO Exception while parsing file '%s'.", file.getName());
                            throw new ExtractionException(msg, ex);
                        } finally {
                            if (bos != null) {
                                try {
                                    bos.close();
                                } catch (IOException ex) {
                                    LOGGER.log(Level.FINEST, null, ex);
                                }
                            }
                        }
                    }
                }
            }
        } catch (IOException ex) {
            final String msg = String.format("Exception reading archive '%s'.", archive.getName());
            LOGGER.log(Level.FINE, msg, ex);
            throw new ExtractionException(msg, ex);
        } finally {
            try {
                zis.close();
            } catch (IOException ex) {
                LOGGER.log(Level.FINEST, null, ex);
            }
        }
    }
}
