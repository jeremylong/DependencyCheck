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
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.update;

/**
 * A pojo that contains the Url and timestamp of the current NvdCve XML files.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class NvdCveInfo {

    /**
     * an id.
     */
    private String id;

    /**
     * Get the value of id.
     *
     * @return the value of id
     */
    public String getId() {
        return id;
    }

    /**
     * Set the value of id.
     *
     * @param id new value of id
     */
    public void setId(String id) {
        this.id = id;
    }
    /**
     * a url.
     */
    private String url;

    /**
     * Get the value of url.
     *
     * @return the value of url
     */
    public String getUrl() {
        return url;
    }

    /**
     * Set the value of url.
     *
     * @param url new value of url
     */
    public void setUrl(String url) {
        this.url = url;
    }
    /**
     * The 1.2 schema URL.
     */
    private String oldSchemaVersionUrl;

    /**
     * Get the value of oldSchemaVersionUrl.
     *
     * @return the value of oldSchemaVersionUrl
     */
    public String getOldSchemaVersionUrl() {
        return oldSchemaVersionUrl;
    }

    /**
     * Set the value of oldSchemaVersionUrl.
     *
     * @param oldSchemaVersionUrl new value of oldSchemaVersionUrl
     */
    public void setOldSchemaVersionUrl(String oldSchemaVersionUrl) {
        this.oldSchemaVersionUrl = oldSchemaVersionUrl;
    }
    /**
     * a timestamp - epoch time.
     */
    private long timestamp;

    /**
     * Get the value of timestamp - epoch time.
     *
     * @return the value of timestamp - epoch time
     */
    public long getTimestamp() {
        return timestamp;
    }

    /**
     * Set the value of timestamp - epoch time.
     *
     * @param timestamp new value of timestamp - epoch time
     */
    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }
    /**
     * indicates whether or not this item should be updated.
     */
    private boolean needsUpdate = true;

    /**
     * Get the value of needsUpdate.
     *
     * @return the value of needsUpdate
     */
    public boolean getNeedsUpdate() {
        return needsUpdate;
    }

    /**
     * Set the value of needsUpdate.
     *
     * @param needsUpdate new value of needsUpdate
     */
    public void setNeedsUpdate(boolean needsUpdate) {
        this.needsUpdate = needsUpdate;
    }
}
