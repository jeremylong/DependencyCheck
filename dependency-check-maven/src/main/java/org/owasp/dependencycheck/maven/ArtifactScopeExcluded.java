/*
 * This file is part of dependency-check-maven.
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
 * Copyright (c) 2017 Josh Cain. All Rights Reserved.
 */
package org.owasp.dependencycheck.maven;

import org.owasp.dependencycheck.utils.Filter;
import static org.apache.maven.artifact.Artifact.SCOPE_COMPILE_PLUS_RUNTIME;
import static org.apache.maven.artifact.Artifact.SCOPE_RUNTIME;
import static org.apache.maven.artifact.Artifact.SCOPE_SYSTEM;
import static org.apache.maven.artifact.Artifact.SCOPE_TEST;
import static org.apache.maven.artifact.Artifact.SCOPE_PROVIDED;

/**
 * Utility class to determine if an artifact should be excluded.
 *
 * @author Josh Cain
 */
public class ArtifactScopeExcluded extends Filter<String> {

    /**
     * Whether or not to skip the test scope.
     */
    private final boolean skipTestScope;
    /**
     * Whether or not to skip the provided scope.
     */
    private final boolean skipProvidedScope;
    /**
     * Whether or not to skip the system scope.
     */
    private final boolean skipSystemScope;
    /**
     * Whether or not to skip the runtime scope.
     */
    private final boolean skipRuntimeScope;

    /**
     * Constructs a new ArtifactScopeExcluded object.
     *
     * @param skipTestScope whether or not to skip the test scope
     * @param skipProvidedScope whether or not to skip the provided scope
     * @param skipSystemScope whether or not to skip the system scope
     * @param skipRuntimeScope whether or not to skip the runtime scope
     */
    public ArtifactScopeExcluded(final boolean skipTestScope, final boolean skipProvidedScope,
            final boolean skipSystemScope, final boolean skipRuntimeScope) {
        this.skipTestScope = skipTestScope;
        this.skipProvidedScope = skipProvidedScope;
        this.skipSystemScope = skipSystemScope;
        this.skipRuntimeScope = skipRuntimeScope;
    }

    /**
     * Tests is the artifact should be included in the scan (i.e. is the
     * dependency in a scope that is being scanned).
     *
     * @param scope the scope of the artifact to test
     * @return <code>true</code> if the artifact is in an excluded scope;
     * otherwise <code>false</code>
     */
    @Override
    public boolean passes(final String scope) {
        if (skipTestScope && SCOPE_TEST.equals(scope)) {
            return true;
        }
        if (skipProvidedScope && SCOPE_PROVIDED.equals(scope)) {
            return true;
        }
        if (skipSystemScope && SCOPE_SYSTEM.equals(scope)) {
            return true;
        }
        if (skipRuntimeScope && SCOPE_RUNTIME.equals(scope)) {
            return true;
        }
        if (skipRuntimeScope && skipSystemScope && SCOPE_COMPILE_PLUS_RUNTIME.equals(scope)) {
            return true;
        }
        return false;
    }
}
