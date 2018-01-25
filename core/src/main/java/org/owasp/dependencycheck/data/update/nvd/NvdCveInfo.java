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
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.update.nvd;

import javax.annotation.concurrent.ThreadSafe;

/**
 * A pojo that contains the Url and timestamp of the current NvdCve XML files.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class NvdCveInfo {

    /**
     * an id.
     */
    private String id;
    /**
     * a url.
     */
    private String url;
    /**
     * The 1.2 schema URL.
     */
    private String oldSchemaVersionUrl;
    /**
     * a timestamp - epoch time.
     */
    private long timestamp;
    /**
     * indicates whether or not this item should be updated.
     */
    private boolean needsUpdate = true;

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
