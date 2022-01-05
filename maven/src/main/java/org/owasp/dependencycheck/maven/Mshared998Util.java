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
 * Copyright (c) 2021 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.maven;

import org.apache.maven.RepositoryUtils;
import org.apache.maven.shared.transfer.artifact.resolve.ArtifactResult;
import org.eclipse.aether.resolution.DependencyResolutionException;
import org.eclipse.aether.resolution.DependencyResult;

import java.util.ArrayList;
import java.util.List;

public final class Mshared998Util {

    /**
     * Empty constructor to prevent instantiation of utility-class.
     */
    private Mshared998Util() {
    }

    /**
     * Get the list of ArtifactResults from a resolution that ran into an exception.
     *
     * @param adre
     *         The DependencyResolutionException that might have embedded resolution results
     *
     * @return The list of ArtifactResults created from the dependencyResult of the exception.
     */
    public static List<ArtifactResult> getResolutionResults(DependencyResolutionException adre) {
        final DependencyResult dependencyResult = adre.getResult();
        final List<ArtifactResult> results = new ArrayList<>();
        if (dependencyResult != null) {
            for (org.eclipse.aether.resolution.ArtifactResult artifactResult : dependencyResult.getArtifactResults()) {
                results.add(new M31ArtifactResult(artifactResult));
            }
        }
        return results;
    }

    /**
     * Our own implementation of ArtifactResult because MShared library does not expose the
     * transformation from eclipse aether ArtifactResult to maven-shared ArtifactResult.
     * So we cannot reuse Maven's own implementation in
     * org.apache.maven.shared.transfer.artifact.resolve.internal
     * This class is a copy of it, but then hard-bound to eclipse aether implementation
     * as DependencyCheck is already not compatible with maven 3.0
     */
    static class M31ArtifactResult implements ArtifactResult {

        /**
         * The ArtifactResult of the Maven 3.1+ artifact resolution
         * implementation library (Eclipse Aether) that is wrapped by this instance
         */
        private final org.eclipse.aether.resolution.ArtifactResult artifactResult;

        /**
         * @param artifactResult
         *         {@link ArtifactResult}
         */
        M31ArtifactResult(org.eclipse.aether.resolution.ArtifactResult artifactResult) {
            this.artifactResult = artifactResult;
        }

        @Override
        public org.apache.maven.artifact.Artifact getArtifact() {
            return RepositoryUtils.toArtifact(artifactResult.getArtifact());
        }
    }
}
