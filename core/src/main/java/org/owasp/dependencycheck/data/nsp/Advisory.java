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
 * Copyright (c) 2017 Steve Springett. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nsp;

import java.util.Arrays;
import javax.annotation.concurrent.ThreadSafe;

/**
 * The response from NSP check API will respond with 0 or more advisories. This
 * class defines the Advisory objects returned.
 *
 * @author Steve Springett
 */
@ThreadSafe
public class Advisory {

    /**
     * The unique ID of the advisory as issued by Node Security Platform.
     */
    private int id;

    /**
     * The timestamp of the last update to the advisory.
     */
    private String updatedAt;

    /**
     * The timestamp of which the advisory was created.
     */
    private String createdAt;

    /**
     * The timestamp of when the advisory was published.
     */
    private String publishDate;

    /**
     * A detailed description of the advisory.
     */
    private String overview;

    /**
     * Recommendations for mitigation. Typically involves updating to a newer
     * release.
     */
    private String recommendation;

    /**
     * The CVSS vector used to calculate the score.
     */
    private String cvssVector;

    /**
     * The CVSS score.
     */
    private float cvssScore;

    /**
     * The name of the Node module the advisory is for.
     */
    private String module;

    /**
     * The version of the Node module the advisory is for.
     */
    private String version;

    /**
     * A string representation of the versions containing the vulnerability.
     */
    private String vulnerableVersions;

    /**
     * A string representation of the versions that have been patched.
     */
    private String patchedVersions;

    /**
     * The title/name of the advisory.
     */
    private String title;

    /**
     * The linear dependency path that lead to this module. [0] is the root with
     * each subsequent array member leading up to the final (this) module.
     */
    private String[] path;

    /**
     * The URL to the advisory.
     */
    private String advisory;

    /**
     * Returns the unique ID of the advisory as issued by Node Security
     * Platform.
     *
     * @return a unique ID
     */
    public int getId() {
        return id;
    }

    /**
     * Sets the unique ID of the advisory as issued by Node Security Platform.
     *
     * @param id a unique ID
     */
    public void setId(int id) {
        this.id = id;
    }

    /**
     * Returns the timestamp of the last update to the advisory.
     *
     * @return a timestamp
     */
    public String getUpdatedAt() {
        return updatedAt;
    }

    /**
     * Sets the timestamp of the last update to the advisory.
     *
     * @param updatedAt a timestamp
     */
    public void setUpdatedAt(String updatedAt) {
        this.updatedAt = updatedAt;
    }

    /**
     * Returns the timestamp of which the advisory was created.
     *
     * @return a timestamp
     */
    public String getCreatedAt() {
        return createdAt;
    }

    /**
     * Sets the timestamp of which the advisory was created.
     *
     * @param createdAt a timestamp
     */
    public void setCreatedAt(String createdAt) {
        this.createdAt = createdAt;
    }

    /**
     * Returns the timestamp of when the advisory was published.
     *
     * @return a timestamp
     */
    public String getPublishDate() {
        return publishDate;
    }

    /**
     * Sets the timestamp of when the advisory was published.
     *
     * @param publishDate a timestamp
     */
    public void setPublishDate(String publishDate) {
        this.publishDate = publishDate;
    }

    /**
     * Returns a detailed description of the advisory.
     *
     * @return the overview
     */
    public String getOverview() {
        return overview;
    }

    /**
     * Sets the detailed description of the advisory.
     *
     * @param overview the overview
     */
    public void setOverview(String overview) {
        this.overview = overview;
    }

    /**
     * Returns recommendations for mitigation. Typically involves updating to a
     * newer release.
     *
     * @return recommendations
     */
    public String getRecommendation() {
        return recommendation;
    }

    /**
     * Sets recommendations for mitigation. Typically involves updating to a
     * newer release.
     *
     * @param recommendation recommendations
     */
    public void setRecommendation(String recommendation) {
        this.recommendation = recommendation;
    }

    /**
     * Returns the CVSS vector used to calculate the score.
     *
     * @return the CVSS vector
     */
    public String getCvssVector() {
        return cvssVector;
    }

    /**
     * Sets the CVSS vector used to calculate the score.
     *
     * @param cvssVector the CVSS vector
     */
    public void setCvssVector(String cvssVector) {
        this.cvssVector = cvssVector;
    }

    /**
     * Returns the CVSS score.
     *
     * @return the CVSS score
     */
    public float getCvssScore() {
        return cvssScore;
    }

    /**
     * Sets the CVSS score.
     *
     * @param cvssScore the CVSS score
     */
    public void setCvssScore(float cvssScore) {
        this.cvssScore = cvssScore;
    }

    /**
     * Returns the name of the Node module the advisory is for.
     *
     * @return the name of the module
     */
    public String getModule() {
        return module;
    }

    /**
     * Sets the name of the Node module the advisory is for.
     *
     * @param module the name of the4 module
     */
    public void setModule(String module) {
        this.module = module;
    }

    /**
     * Returns the version of the Node module the advisory is for.
     *
     * @return the module version
     */
    public String getVersion() {
        return version;
    }

    /**
     * Sets the version of the Node module the advisory is for.
     *
     * @param version the module version
     */
    public void setVersion(String version) {
        this.version = version;
    }

    /**
     * Returns a string representation of the versions containing the
     * vulnerability.
     *
     * @return the affected versions
     */
    public String getVulnerableVersions() {
        return vulnerableVersions;
    }

    /**
     * Sets the string representation of the versions containing the
     * vulnerability.
     *
     * @param vulnerableVersions the affected versions
     */
    public void setVulnerableVersions(String vulnerableVersions) {
        this.vulnerableVersions = vulnerableVersions;
    }

    /**
     * Returns a string representation of the versions that have been patched.
     *
     * @return the patched versions
     */
    public String getPatchedVersions() {
        return patchedVersions;
    }

    /**
     * Sets the string representation of the versions that have been patched.
     *
     * @param patchedVersions the patched versions
     */
    public void setPatchedVersions(String patchedVersions) {
        this.patchedVersions = patchedVersions;
    }

    /**
     * Returns the title/name of the advisory.
     *
     * @return the title/name of the advisory
     */
    public String getTitle() {
        return title;
    }

    /**
     * Sets the title/name of the advisory.
     *
     * @param title the title/name of the advisory
     */
    public void setTitle(String title) {
        this.title = title;
    }

    /**
     * Returns the linear dependency path that lead to this module.
     *
     * @return the dependency path
     */
    public String[] getPath() {
        if (path == null) {
            return null;
        }
        return Arrays.copyOf(path, path.length);
    }

    /**
     * Sets the linear dependency path that lead to this module.
     *
     * @param path the dependency path
     */
    public void setPath(String[] path) {
        if (path == null) {
            this.path = null;
        } else {
            this.path = Arrays.copyOf(path, path.length);
        }
    }

    /**
     * Returns the URL to the advisory.
     *
     * @return the advisory URL
     */
    public String getAdvisory() {
        return advisory;
    }

    /**
     * Sets the URL to the advisory.
     *
     * @param advisory the advisory URL
     */
    public void setAdvisory(String advisory) {
        this.advisory = advisory;
    }
}
