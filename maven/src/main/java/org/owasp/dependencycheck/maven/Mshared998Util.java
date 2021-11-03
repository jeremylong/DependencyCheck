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
import org.apache.maven.artifact.Artifact;
import org.apache.maven.shared.transfer.artifact.ArtifactCoordinate;
import org.apache.maven.shared.transfer.dependencies.resolve.DependencyResolverException;
import org.eclipse.aether.resolution.ArtifactResult;
import org.eclipse.aether.resolution.DependencyResolutionException;
import org.eclipse.aether.resolution.DependencyResult;

import java.util.Objects;

public final class Mshared998Util {

    /**
     * Empty constructor to prevent instantiation of utility-class.
     */
    private Mshared998Util() {
    }

    /**
     * Find the artifact for the given coordinate among the available successful
     * resolution attempts contained within the DependencyResolverException.
     *
     * @param dre The DependencyResolverException that might have embedded
     * successful resolution results
     * @param coordinate The coordinates of the artifact we're interested in
     * @return The resolved artifact matching {@code coordinate} or {@code null}
     * if not found
     */
    public static Artifact findArtifactInAetherDREResult(final DependencyResolverException dre,
            final ArtifactCoordinate coordinate) {
        Artifact result = null;
        if (dre.getCause() instanceof DependencyResolutionException) {
            final DependencyResolutionException adre = (DependencyResolutionException) dre.getCause();
            final DependencyResult dependencyResult = adre.getResult();
            if (dependencyResult != null) {
                for (ArtifactResult artifactResult : dependencyResult.getArtifactResults()) {
                    if (matchesCoordinate(artifactResult, coordinate)) {
                        result = RepositoryUtils.toArtifact(artifactResult.getArtifact());
                        break;
                    }
                }
            }
        }
        return result;
    }

    /**
     * Checks whether the given ArtifactResult contains an artifact that matches
     * the coordinate
     *
     * @param artifactResult The ArtifactResult to inspect
     * @param coordinate The coordinate to match with
     * @return {@code true} when the artifactresult contains an artifact that
     * matches the coordinate on GAV_C_E, false otherwise.
     */
    private static boolean matchesCoordinate(final ArtifactResult artifactResult, final ArtifactCoordinate coordinate) {
        if (artifactResult.getArtifact() == null) {
            return false;
        } else {
            final org.eclipse.aether.artifact.Artifact artifact = artifactResult.getArtifact();
            boolean result = Objects.equals(artifact.getGroupId(), coordinate.getGroupId());
            result &= Objects.equals(artifact.getArtifactId(), coordinate.getArtifactId());
            result &= Objects.equals(artifact.getVersion(), coordinate.getVersion());
            result &= Objects.equals(artifact.getClassifier(), coordinate.getClassifier());
            result &= Objects.equals(artifact.getExtension(), coordinate.getExtension());
            return result;
        }
    }
}
