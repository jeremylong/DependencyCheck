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
 * A pojo that contains the Url and timestamp of the current NvdCve JSON files.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class NvdCveInfo {

    /**
     * The identifier for the CVE data file.
     */
    private final String id;
    /**
     * The URL to download the file.
     */
    private final String url;
    /**
     * The timestamp of the file - epoch time.
     */
    private final long timestamp;

    /**
     * Construct a new NVD CVE Info object.
     *
     * @param id the id
     * @param url the url
     * @param timestamp the timestamp
     */
    public NvdCveInfo(String id, String url, long timestamp) {
        this.id = id;
        this.url = url;
        this.timestamp = timestamp;
    }

    /**
     * Get the value of id.
     *
     * @return the value of id
     */
    public String getId() {
        return id;
    }

    /**
     * Get the value of URL.
     *
     * @return the value of URL
     */
    public String getUrl() {
        return url;
    }

    /**
     * Get the value of timestamp - epoch time.
     *
     * @return the value of timestamp - epoch time
     */
    public long getTimestamp() {
        return timestamp;
    }
}
