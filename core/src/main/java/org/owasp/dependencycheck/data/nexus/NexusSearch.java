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
 * Copyright (c) 2023 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nexus;

import java.io.IOException;

public interface NexusSearch {
    /**
     * Searches the configured Nexus repository for the given sha1 hash. If the
     * artifact is found, a <code>MavenArtifact</code> is populated with the
     * coordinate information.
     *
     * @param sha1 The SHA-1 hash string for which to search
     * @return the populated Maven coordinates
     * @throws IOException if it's unable to connect to the specified repository
     *                     or if the specified artifact is not found.
     */
    MavenArtifact searchSha1(String sha1) throws IOException;

    /**
     * Do a preflight request to see if the repository is actually working.
     *
     * @return whether the repository is listening and returns the expected status response
     */
    boolean preflightRequest();
}
