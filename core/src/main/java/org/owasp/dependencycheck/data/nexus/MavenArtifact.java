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
package org.owasp.dependencycheck.data.nexus;

import java.io.Serializable;
import javax.annotation.concurrent.ThreadSafe;

/**
 * Simple bean representing a Maven Artifact.
 *
 * @author colezlaw
 * @author nhenneaux
 */
@ThreadSafe
public class MavenArtifact implements Serializable {

    /**
     * Generated UID.
     */
    private static final long serialVersionUID = -9112154330099159722L;
    /**
     * The base URL for download artifacts from Central.
     */
    private static final String CENTRAL_CONTENT_URL = "https://search.maven.org/remotecontent?filepath=";

    /**
     * The groupId
     */
    private String groupId;

    /**
     * The artifactId
     */
    private String artifactId;

    /**
     * The version
     */
    private String version;

    /**
     * The artifact url. This may change depending on which Nexus server the
     * search took place.
     */
    private String artifactUrl;
    /**
     * The url to download the POM from.
     */
    private String pomUrl;

    /**
     * Creates an empty MavenArtifact.
     */
    public MavenArtifact() {
    }

    /**
     * Creates a MavenArtifact with the given attributes.
     *
     * @param groupId the groupId
     * @param artifactId the artifactId
     * @param version the version
     */
    public MavenArtifact(String groupId, String artifactId, String version) {
        this.groupId = groupId;
        this.artifactId = artifactId;
        this.version = version;
    }

    /**
     * Creates a MavenArtifact with the given attributes.
     *
     * @param groupId the groupId
     * @param artifactId the artifactId
     * @param version the version
     * @param jarAvailable if the jar file is available from central
     * @param pomAvailable if the pom file is available from central
     */
    public MavenArtifact(String groupId, String artifactId, String version, boolean jarAvailable, boolean pomAvailable) {
        this.groupId = groupId;
        this.artifactId = artifactId;
        this.version = version;
        if (jarAvailable) {
            //org/springframework/spring-core/3.2.0.RELEASE/spring-core-3.2.0.RELEASE.pom
            this.artifactUrl = CENTRAL_CONTENT_URL + groupId.replace('.', '/') + '/' + artifactId + '/'
                    + version + '/' + artifactId + '-' + version + ".jar";
        }
        if (pomAvailable) {
            //org/springframework/spring-core/3.2.0.RELEASE/spring-core-3.2.0.RELEASE.pom
            this.pomUrl = CENTRAL_CONTENT_URL + groupId.replace('.', '/') + '/' + artifactId + '/'
                    + version + '/' + artifactId + '-' + version + ".pom";
        }
    }

    /**
     * Creates a MavenArtifact with the given attributes.
     *
     * @param groupId the groupId
     * @param artifactId the artifactId
     * @param version the version
     * @param url the artifactLink url
     */
    public MavenArtifact(String groupId, String artifactId, String version, String url) {
        this.groupId = groupId;
        this.artifactId = artifactId;
        this.version = version;
        this.artifactUrl = url;
    }

    /**
     * Creates a MavenArtifact with the given attributes.
     *
     * @param groupId the groupId
     * @param artifactId the artifactId
     * @param version the version
     * @param artifactUrl the artifactLink url
     * @param pomUrl the pomUrl
     */
    public MavenArtifact(String groupId, String artifactId, String version, String artifactUrl, String pomUrl) {
        this.groupId = groupId;
        this.artifactId = artifactId;
        this.version = version;
        this.artifactUrl = artifactUrl;
        this.pomUrl = pomUrl;
    }

    /**
     * Tries to determine the URL to the pom.xml.
     *
     * @param artifactId the artifact id
     * @param version the version
     * @param artifactUrl the artifact URL
     * @return the string representation of the URL
     */
    public static String derivePomUrl(String artifactId, String version, String artifactUrl) {
        return artifactUrl.substring(0, artifactUrl.lastIndexOf('/')) + '/' + artifactId + '-' + version + ".pom";
    }

    /**
     * Returns the Artifact coordinates as a String.
     *
     * @return the String representation of the artifact coordinates
     */
    @Override
    public String toString() {
        return String.format("%s:%s:%s", groupId, artifactId, version);
    }

    /**
     * Gets the groupId.
     *
     * @return the groupId
     */
    public String getGroupId() {
        return groupId;
    }

    /**
     * Sets the groupId.
     *
     * @param groupId the groupId
     */
    public void setGroupId(String groupId) {
        this.groupId = groupId;
    }

    /**
     * Gets the artifactId.
     *
     * @return the artifactId
     */
    public String getArtifactId() {
        return artifactId;
    }

    /**
     * Sets the artifactId.
     *
     * @param artifactId the artifactId
     */
    public void setArtifactId(String artifactId) {
        this.artifactId = artifactId;
    }

    /**
     * Gets the version.
     *
     * @return the version
     */
    public String getVersion() {
        return version;
    }

    /**
     * Sets the version.
     *
     * @param version the version
     */
    public void setVersion(String version) {
        this.version = version;
    }

    /**
     * Gets the artifactUrl.
     *
     * @return the artifactUrl
     */
    public String getArtifactUrl() {
        return artifactUrl;
    }

    /**
     * Sets the artifactUrl.
     *
     * @param artifactUrl the artifactUrl
     */
    public void setArtifactUrl(String artifactUrl) {
        this.artifactUrl = artifactUrl;
    }

    /**
     * Get the value of pomUrl.
     *
     * @return the value of pomUrl
     */
    public String getPomUrl() {
        return pomUrl;
    }

    /**
     * Set the value of pomUrl.
     *
     * @param pomUrl new value of pomUrl
     */
    public void setPomUrl(String pomUrl) {
        this.pomUrl = pomUrl;
    }

}
