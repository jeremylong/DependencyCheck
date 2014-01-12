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
package org.owasp.dependencycheck.data.nvdcve;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import junit.framework.TestCase;
import org.owasp.dependencycheck.utils.Settings;

/**
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public abstract class BaseDBTestCase extends TestCase {

    protected final static int BUFFER_SIZE = 2048;

    @Override
    protected void setUp() throws Exception {
        super.setUp();
        ensureDBExists();
    }

    public static void ensureDBExists() throws Exception {

        java.io.File dataPath = Settings.getDataFile(Settings.KEYS.DATA_DIRECTORY);
        if (!dataPath.exists() || (dataPath.isDirectory() && dataPath.listFiles().length < 3)) {
            dataPath.mkdirs();
            FileInputStream fis = null;
            ZipInputStream zin = null;
            try {
                File path = new File(BaseDBTestCase.class.getClassLoader().getResource("data.zip").getPath());
                fis = new FileInputStream(path);
                zin = new ZipInputStream(new BufferedInputStream(fis));
                ZipEntry entry;
                while ((entry = zin.getNextEntry()) != null) {
                    if (entry.isDirectory()) {
                        final File d = new File(dataPath, entry.getName());
                        d.mkdir();
                        continue;
                    }
                    FileOutputStream fos = null;
                    BufferedOutputStream dest = null;
                    try {
                        File o = new File(dataPath, entry.getName());
                        o.createNewFile();
                        fos = new FileOutputStream(o, false);
                        dest = new BufferedOutputStream(fos, BUFFER_SIZE);
                        byte data[] = new byte[BUFFER_SIZE];
                        int count;
                        while ((count = zin.read(data, 0, BUFFER_SIZE)) != -1) {
                            dest.write(data, 0, count);
                        }
                    } catch (Exception ex) {
                        Logger.getLogger(BaseDBTestCase.class.getName()).log(Level.SEVERE, null, ex);
                    } finally {
                        try {
                            if (dest != null) {
                                dest.flush();
                                dest.close();
                            }
                        } catch (Throwable ex) {
                            Logger.getLogger(BaseDBTestCase.class.getName()).log(Level.FINEST, null, ex);
                        }
                        try {
                            if (fos != null) {
                                fos.close();
                            }
                        } catch (Throwable ex) {
                            Logger.getLogger(BaseDBTestCase.class.getName()).log(Level.FINEST, null, ex);
                        }
                    }
                }
            } finally {
                try {
                    if (zin != null) {
                        zin.close();
                    }
                } catch (Throwable ex) {
                    Logger.getLogger(BaseDBTestCase.class.getName()).log(Level.FINEST, null, ex);
                }
                try {
                    if (fis != null) {
                        fis.close();
                    }
                } catch (Throwable ex) {
                    Logger.getLogger(BaseDBTestCase.class.getName()).log(Level.FINEST, null, ex);
                }
            }
        }
    }
}
