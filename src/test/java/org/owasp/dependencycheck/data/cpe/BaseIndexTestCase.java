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
package org.owasp.dependencycheck.data.cpe;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.owasp.dependencycheck.utils.FileUtils;
import org.owasp.dependencycheck.utils.Settings;

/**
 *
 * @author Jeremy Long (jeremy.long@owasp.org)
 */
public abstract class BaseIndexTestCase {

    @BeforeClass
    public static void setUpClass() throws Exception {
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
    }

    @Before
    public void setUp() throws Exception {
        ensureIndexExists();
    }

    @After
    public void tearDown() throws Exception {
    }

    protected static File getDataDirectory() throws IOException {
        String fileName = Settings.getString(Settings.KEYS.CPE_INDEX);
        return FileUtils.getDataDirectory(fileName, Index.class);
    }

    public static void ensureIndexExists() throws Exception {
        //String indexPath = Settings.getString(Settings.KEYS.CPE_INDEX);
        String indexPath = getDataDirectory().getCanonicalPath();
        java.io.File f = new File(indexPath);
        if (!f.exists()) {
            f.mkdirs();
            FileInputStream fis = null;
            ZipInputStream zin = null;
            try {
                File path = new File(BaseIndexTestCase.class.getClassLoader().getResource("index.cpe.zip").getPath());
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
                        fos = new FileOutputStream(o,false);
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
                        } catch (Throwable ex) { String ignore = ex.getMessage(); }
                        try {
                            fos.close();
                            fos = null;
                        } catch (Throwable ex) { String ignore = ex.getMessage(); }
                    }
                }
            } finally {
                try {
                    if (zin!=null) {
                        zin.close();
                    }
                    zin = null;
                } catch (Throwable ex) { String ignore = ex.getMessage(); }
                try {
                    if (fis!=null) {
                        fis.close();
                    }
                    fis = null;
                } catch (Throwable ex) { String ignore = ex.getMessage(); }
            }
        }
    }
}
