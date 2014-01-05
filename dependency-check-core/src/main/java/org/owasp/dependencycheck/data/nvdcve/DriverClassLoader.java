/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.owasp.dependencycheck.data.nvdcve;

import java.io.File;
import java.net.URL;
import java.net.URLClassLoader;

/**
 *
 * @author Jeremy Long (jeremy.long@owasp.org)
 */
public class DriverClassLoader extends URLClassLoader {

    /**
     * Constructs a new DriverClassLoader that performs a deep copy of the URLs
     * in the provided class loader.
     *
     */
    public DriverClassLoader(File pathToDriver, ClassLoader parent) {
        File driverFolder = new File("driver");
        File[] files = driverFolder.listFiles();
        for (File file : files) {
            try {
                loader.addURL(file.toURI().toURL());
            } catch (MalformedURLException e) {
            }
        }

        super(urls, parent);
    }

    /**
     * Add additional URLs to the class loader.
     *
     * @param url the URL to add to the class loader
     */
    @Override
    public void addURL(URL url) {
        super.addURL(url);
    }
}
