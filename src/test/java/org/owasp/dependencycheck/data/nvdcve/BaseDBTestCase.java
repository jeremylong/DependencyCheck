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
package org.owasp.dependencycheck.data.nvdcve;

import org.owasp.dependencycheck.data.cpe.*;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import junit.framework.TestCase;
import org.owasp.dependencycheck.utils.FileUtils;
import org.owasp.dependencycheck.utils.Settings;

/**
 *
 * @author Jeremy Long (jeremy.long@owasp.org)
 */
public abstract class BaseDBTestCase extends TestCase {

    public BaseDBTestCase(String testName) {
        super(testName);
    }

    @Override
    protected void setUp() throws Exception {
        super.setUp();
        ensureDBExists();
    }

    protected static File getDataDirectory() throws IOException {
        String fileName = Settings.getString(Settings.KEYS.CVE_INDEX);
        File exePath = FileUtils.getDataDirectory(fileName, Index.class);
        if (exePath.getName().toLowerCase().endsWith(".jar")) {
            exePath = exePath.getParentFile();
        } else {
            exePath = new File(".");
        }
        File path = new File(exePath.getCanonicalFile() + File.separator + fileName);
        path = new File(path.getCanonicalPath());
        return path;
    }

    public static void ensureDBExists() throws Exception {
        //String indexPath = Settings.getString(Settings.KEYS.CVE_INDEX);
        String indexPath = getDataDirectory().getCanonicalPath();
        java.io.File f = new File(indexPath);
        if (!f.exists()) {
            f.mkdirs();
            FileInputStream fis = null;
            ZipInputStream zin = null;
            try {
                File path = new File(BaseDBTestCase.class.getClassLoader().getResource("db.nvdcve.zip").getPath());
                fis = new FileInputStream(path);
                zin = new ZipInputStream(new BufferedInputStream(fis));
                ZipEntry entry;
                while ((entry = zin.getNextEntry()) != null) {
                    if (entry.isDirectory()) {
                        continue;
                    }
                    int BUFFER = 2048;
                    String outputName = indexPath + File.separatorChar + entry.getName();
                    FileOutputStream fos = null;
                    BufferedOutputStream dest = null;
                    try {
                        File o = new File(outputName);
//                        File oPath = new File(o.getParent());
//                        if (!oPath.exists()) {
//                            oPath.mkdir();
//                        }
                        o.createNewFile();
                        fos = new FileOutputStream(o, false);
                        dest = new BufferedOutputStream(fos, BUFFER);
                        byte data[] = new byte[BUFFER];
                        int count;
                        while ((count = zin.read(data, 0, BUFFER)) != -1) {
                            dest.write(data, 0, count);
                        }
                    } catch (Exception ex) {
                        String ignore = ex.getMessage();
                    } finally {
                        try {
                            dest.flush();
                            dest.close();
                            dest = null;
                        } catch (Throwable ex) {
                            String ignore = ex.getMessage();
                        }
                        try {
                            fos.close();
                            fos = null;
                        } catch (Throwable ex) {
                            String ignore = ex.getMessage();
                        }
                    }
                }
            } finally {
                try {
                    if (zin != null) {
                        zin.close();
                    }
                    zin = null;
                } catch (Throwable ex) {
                    String ignore = ex.getMessage();
                }
                try {
                    if (fis != null) {
                        fis.close();
                    }
                    fis = null;
                } catch (Throwable ex) {
                    String ignore = ex.getMessage();
                }
            }
        }
    }
}
