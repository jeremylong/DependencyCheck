/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.codesecure.dependencycheck.data.nvdcve;

import org.codesecure.dependencycheck.data.cpe.*;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URLDecoder;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import junit.framework.TestCase;
import org.codesecure.dependencycheck.utils.Settings;

/**
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
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
        String filePath = Index.class.getProtectionDomain().getCodeSource().getLocation().getPath();
        String decodedPath = URLDecoder.decode(filePath, "UTF-8");
        File exePath = new File(decodedPath);
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
