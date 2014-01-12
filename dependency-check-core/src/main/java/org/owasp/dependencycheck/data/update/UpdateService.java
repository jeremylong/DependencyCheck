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
package org.owasp.dependencycheck.data.update;

import java.util.Iterator;
import java.util.ServiceLoader;

/**
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public final class UpdateService {

    /**
     * the singleton reference to the service.
     */
    private static UpdateService service;
    /**
     * the service loader for CachedWebDataSource.
     */
    private final ServiceLoader<CachedWebDataSource> loader;

    /**
     * Creates a new instance of UpdateService
     */
    private UpdateService() {
        loader = ServiceLoader.load(CachedWebDataSource.class);
    }

    /**
     * Retrieve the singleton instance of UpdateService.
     *
     * @return a singleton UpdateService.
     */
    public static synchronized UpdateService getInstance() {
        if (service == null) {
            service = new UpdateService();
        }
        return service;
    }

    /**
     * Returns an Iterator for all instances of the CachedWebDataSource
     * interface.
     *
     * @return an iterator of CachedWebDataSource.
     */
    public Iterator<CachedWebDataSource> getDataSources() {
        return loader.iterator();
    }
}
