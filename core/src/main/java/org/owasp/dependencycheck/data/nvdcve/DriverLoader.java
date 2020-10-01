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
 * Copyright (c) 2014 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nvdcve;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.concurrent.ThreadSafe;

/**
 * DriverLoader is a utility class that is used to load database drivers.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public final class DriverLoader {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(DriverLoader.class);

    /**
     * De-registers the driver.
     *
     * @param driver the driver to de-register
     */
    public static void cleanup(Driver driver) {
        try {
            LOGGER.debug("Begin deregister driver");
            DriverManager.deregisterDriver(driver);
            LOGGER.debug("End deregister driver");
        } catch (SQLException ex) {
            LOGGER.debug("An error occurred unloading the database driver", ex);
        } catch (Throwable unexpected) {
            LOGGER.debug("An unexpected throwable occurred unloading the database driver", unexpected);
        }
    }

    /**
     * Private constructor for a utility class.
     */
    private DriverLoader() {
    }

    /**
     * Loads the specified class using the system class loader and registers the
     * driver with the driver manager.
     *
     * @param className the fully qualified name of the desired class
     * @return the loaded Driver
     * @throws DriverLoadException thrown if the driver cannot be loaded
     */
    public static Driver load(String className) throws DriverLoadException {
        final ClassLoader loader = DriverLoader.class.getClassLoader();
        return load(className, loader);
    }

    /**
     * Loads the specified class by registering the supplied paths to the class
     * loader and then registers the driver with the driver manager. The
     * pathToDriver argument is added to the class loader so that an external
     * driver can be loaded. Note, the pathToDriver can contain a semi-colon
     * separated list of paths so any dependencies can be added as needed. If a
     * path in the pathToDriver argument is a directory all files in the
     * directory are added to the class path.
     *
     * @param className the fully qualified name of the desired class
     * @param pathToDriver the path to the JAR file containing the driver; note,
     * this can be a semi-colon separated list of paths
     * @return the loaded Driver
     * @throws DriverLoadException thrown if the driver cannot be loaded
     */
    @SuppressWarnings("StringSplitter")
    public static Driver load(String className, String pathToDriver) throws DriverLoadException {
        final ClassLoader parent = ClassLoader.getSystemClassLoader();
        final List<URL> urls = new ArrayList<>();
        final String[] paths = pathToDriver.split(File.pathSeparator);
        for (String path : paths) {
            final File file = new File(path);
            if (file.isDirectory()) {
                final File[] files = file.listFiles();
                if (files != null) {
                    for (File f : files) {
                        try {
                            urls.add(f.toURI().toURL());
                        } catch (MalformedURLException ex) {
                            LOGGER.debug("Unable to load database driver '{}'; invalid path provided '{}'",
                                    className, f.getAbsoluteFile(), ex);
                            throw new DriverLoadException("Unable to load database driver. Invalid path provided", ex);
                        }
                    }
                }
            } else if (file.exists()) {
                try {
                    urls.add(file.toURI().toURL());
                } catch (MalformedURLException ex) {
                    LOGGER.debug("Unable to load database driver '{}'; invalid path provided '{}'",
                            className, file.getAbsoluteFile(), ex);
                    throw new DriverLoadException("Unable to load database driver. Invalid path provided", ex);
                }
            }
        }
        final URLClassLoader loader = AccessController.doPrivileged(new PrivilegedAction<URLClassLoader>() {
            @Override
            public URLClassLoader run() {
                return new URLClassLoader(urls.toArray(new URL[0]), parent);
            }
        });

        return load(className, loader);
    }

    /**
     * Loads the specified class using the supplied class loader and registers
     * the driver with the driver manager.
     *
     * @param className the fully qualified name of the desired class
     * @param loader the class loader to use when loading the driver
     * @return the loaded Driver
     * @throws DriverLoadException thrown if the driver cannot be loaded
     */
    private static Driver load(String className, ClassLoader loader) throws DriverLoadException {
        try {
            final Class<?> c = Class.forName(className, true, loader);
            //final Class c = loader.loadClass(className);
            final Driver driver = (Driver) c.getDeclaredConstructor().newInstance();

            //TODO add usage count so we don't de-register a driver that is in use.
            final Driver shim = new DriverShim(driver);
            //using the DriverShim to get around the fact that the DriverManager won't register a driver not in the base class path
            DriverManager.registerDriver(shim);
            return shim;
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException | SQLException
                | NoSuchMethodException | SecurityException | IllegalArgumentException | InvocationTargetException ex) {
            final String msg = String.format("Unable to load database driver '%s'", className);
            LOGGER.debug(msg, ex);
            throw new DriverLoadException(msg, ex);
        }
    }
}
