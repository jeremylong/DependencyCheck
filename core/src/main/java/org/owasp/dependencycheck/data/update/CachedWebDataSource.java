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

import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.data.update.exception.UpdateException;

/**
 * Defines a data source who's data is retrieved from the Internet. This data
 * can be downloaded and the local cache updated.
 *
 * @author Jeremy Long
 */
public interface CachedWebDataSource {

    /**
     * Determines if an update to the current data store is needed, if it is the
     * new data is downloaded from the Internet and imported into the current
     * cached data store.
     *
     * @param engine a reference to the dependency-check engine
     * @return whether or not an update was made to the CveDB
     * @throws UpdateException is thrown if there is an exception downloading
     * the data or updating the data store.
     */
    boolean update(Engine engine) throws UpdateException;

    /**
     * Deletes any locally cached data.
     *
     * @param engine a reference to the dependency-check engine
     * @return <code>true</code> if the purge was successful; otherwise
     * <code>false</code>
     */
    boolean purge(Engine engine);
}
