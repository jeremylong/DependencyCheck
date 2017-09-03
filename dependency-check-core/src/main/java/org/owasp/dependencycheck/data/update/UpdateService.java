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
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.update;

import java.util.Iterator;
import java.util.ServiceLoader;
import javax.annotation.concurrent.NotThreadSafe;

/**
 * The CachedWebDataSource Service Loader. This class loads all services that
 * implement {@link org.owasp.dependencycheck.data.update.CachedWebDataSource}.
 *
 * @author Jeremy Long
 */
@NotThreadSafe
public class UpdateService {

    /**
     * the service loader for CachedWebDataSource.
     */
    private final ServiceLoader<CachedWebDataSource> loader;

    /**
     * Creates a new instance of UpdateService.
     *
     * @param classLoader the ClassLoader to use when dynamically loading
     * Analyzer and Update services
     */
    public UpdateService(ClassLoader classLoader) {
        loader = ServiceLoader.load(CachedWebDataSource.class, classLoader);
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
