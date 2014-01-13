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
 * Copyright (c) 2014 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nvdcve;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * DriverLoader is a utility class that is used to load database drivers.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public final class DriverLoader {

    /**
     * Private constructor for a utility class.
     */
    private DriverLoader() {
    }

    /**
     * Loads the specified class using the system class loader and registers the driver with the driver manager.
     *
     * @param className the fully qualified name of the desired class
     * @throws DriverLoadException thrown if the driver cannot be loaded
     */
    public static void load(String className) throws DriverLoadException {
        final ClassLoader loader = ClassLoader.getSystemClassLoader();
        load(className, loader);
    }

    /**
     * Loads the specified class by registering the supplied paths to the class loader and then registers the driver
     * with the driver manager. The pathToDriver argument is added to the class loader so that an external driver can be
     * loaded. Note, the pathTodriver can contain a semi-colon separated list of paths so any dependencies can be added
     * as needed. If a path in the pathToDriver argument is a directory all files in the directory are added to the
     * class path.
     *
     * @param className the fully qualified name of the desired class
     * @param pathToDriver the path to the JAR file containing the driver; note, this can be a semi-colon separated list
     * of paths
     * @throws DriverLoadException thrown if the driver cannot be loaded
     */
    public static void load(String className, String pathToDriver) throws DriverLoadException {
        final URLClassLoader parent = (URLClassLoader) ClassLoader.getSystemClassLoader();
        final ArrayList<URL> urls = new ArrayList<URL>();
        final String[] paths = pathToDriver.split(File.pathSeparator);
        for (String path : paths) {
            final File file = new File(path);
            if (file.isDirectory()) {
                final File[] files = file.listFiles();

                for (File f : files) {
                    try {
                        urls.add(f.toURI().toURL());
                    } catch (MalformedURLException ex) {
                        final String msg = String.format("Unable to load database driver '%s'; invalid path provided '%s'",
                                className, f.getAbsoluteFile());
                        Logger.getLogger(DriverLoader.class.getName()).log(Level.FINE, msg, ex);
                        throw new DriverLoadException(msg, ex);
                    }
                }
            } else if (file.exists()) {
                try {
                    urls.add(file.toURI().toURL());
                } catch (MalformedURLException ex) {
                    final String msg = String.format("Unable to load database driver '%s'; invalid path provided '%s'",
                            className, file.getAbsoluteFile());
                    Logger.getLogger(DriverLoader.class.getName()).log(Level.FINE, msg, ex);
                    throw new DriverLoadException(msg, ex);
                }
            }
        }
        final URLClassLoader loader = AccessController.doPrivileged(new PrivilegedAction<URLClassLoader>() {
            @Override
            public URLClassLoader run() {
                return new URLClassLoader(urls.toArray(new URL[urls.size()]), parent);
            }
        });

        load(className, loader);
    }

    /**
     * Loads the specified class using the supplied class loader and registers the driver with the driver manager.
     *
     * @param className the fully qualified name of the desired class
     * @param loader the class loader to use when loading the driver
     * @throws DriverLoadException thrown if the driver cannot be loaded
     */
    private static void load(String className, ClassLoader loader) throws DriverLoadException {
        try {
            final Class c = loader.loadClass(className);
            final Driver driver = (Driver) c.newInstance();
            //using the DriverShim to get around the fact that the DriverManager won't register a driver not in the base class path
            DriverManager.registerDriver(new DriverShim(driver));
        } catch (ClassNotFoundException ex) {
            final String msg = String.format("Unable to load database driver '%s'", className);
            Logger.getLogger(DriverLoader.class.getName()).log(Level.FINE, msg, ex);
            throw new DriverLoadException(msg, ex);
        } catch (InstantiationException ex) {
            final String msg = String.format("Unable to load database driver '%s'", className);
            Logger.getLogger(DriverLoader.class.getName()).log(Level.FINE, msg, ex);
            throw new DriverLoadException(msg, ex);
        } catch (IllegalAccessException ex) {
            final String msg = String.format("Unable to load database driver '%s'", className);
            Logger.getLogger(DriverLoader.class.getName()).log(Level.FINE, msg, ex);
            throw new DriverLoadException(msg, ex);
        } catch (SQLException ex) {
            final String msg = String.format("Unable to load database driver '%s'", className);
            Logger.getLogger(DriverLoader.class.getName()).log(Level.FINE, msg, ex);
            throw new DriverLoadException(msg, ex);
        }
    }
}
