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
package org.owasp.dependencycheck.data.update.nvd;

import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeMap;
import javax.annotation.concurrent.NotThreadSafe;

/**
 * Contains a collection of updateable NvdCveInfo objects. This is used to
 * determine which files need to be downloaded and processed.
 *
 * @author Jeremy Long
 */
@NotThreadSafe
public class UpdateableNvdCve implements Iterable<NvdCveInfo>, Iterator<NvdCveInfo> {

    /**
     * A collection of sources of data.
     */
    private final Map<String, NvdCveInfo> collection = new TreeMap<>();

    /**
     * An internal iterator used to implement iterable.
     */
    private Iterator<Entry<String, NvdCveInfo>> iterableContent = null;

    /**
     * Returns the collection of NvdCveInfo objects. This method is mainly used
     * for testing.
     *
     * @return the collection of NvdCveInfo objects
     */
    protected Map<String, NvdCveInfo> getCollection() {
        return collection;
    }

    /**
     * Gets whether or not an update is needed.
     *
     * @return true or false depending on whether an update is needed
     */
    public boolean isUpdateNeeded() {
        for (NvdCveInfo item : this) {
            if (item.getNeedsUpdate()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Adds a new entry of updateable information to the contained collection.
     *
     * @param id the key for the item to be added
     * @param url the URL to download the item
     * @param oldUrl the URL for the old version of the item (the NVD CVE old
     * schema still contains useful data we need).
     * @param timestamp the last modified date of the downloaded item
     * @param needsUpdate whether or not the data needs to be updated
     */
    public void add(String id, String url, String oldUrl, long timestamp, boolean needsUpdate) {
        final NvdCveInfo item = new NvdCveInfo();
        item.setNeedsUpdate(needsUpdate); //the others default to true, to make life easier later this should default to false.
        item.setId(id);
        item.setUrl(url);
        item.setOldSchemaVersionUrl(oldUrl);
        item.setTimestamp(timestamp);
        collection.put(id, item);
    }

    /**
     * Clears the contained collection of NvdCveInfo entries.
     */
    public void clear() {
        collection.clear();
    }

    /**
     * Returns the timestamp for the given entry.
     *
     * @param key the key to lookup in the collection of NvdCveInfo items
     * @return the timestamp for the given entry
     */
    public long getTimeStamp(String key) {
        return collection.get(key).getTimestamp();
    }

    /**
     * <p>
     * Returns an iterator for the NvdCveInfo contained.</p>
     * <p>
     * <b>This method is not thread safe.</b></p>
     *
     * @return an NvdCveInfo Iterator
     */
    @Override
    public Iterator<NvdCveInfo> iterator() {
        iterableContent = collection.entrySet().iterator();
        return this;
    }

    /**
     * <p>
     * Returns whether or not there is another item in the collection.</p>
     * <p>
     * <b>This method is not thread safe.</b></p>
     *
     * @return true or false depending on whether or not another item exists in
     * the collection
     */
    @Override
    public boolean hasNext() {
        return iterableContent.hasNext();
    }

    /**
     * <p>
     * Returns the next item in the collection.</p>
     * <p>
     * <b>This method is not thread safe.</b></p>
     *
     * @return the next NvdCveInfo item in the collection
     */
    @Override
    public NvdCveInfo next() {
        return iterableContent.next().getValue();
    }

    /**
     * <p>
     * Removes the current NvdCveInfo object from the collection.</p>
     * <p>
     * <b>This method is not thread safe.</b></p>
     */
    @Override
    public void remove() {
        iterableContent.remove();
    }

    /**
     * Returns the specified item from the collection.
     *
     * @param key the key to lookup the return value
     * @return the NvdCveInfo object stored using the specified key
     */
    public NvdCveInfo get(String key) {
        return collection.get(key);
    }

    @Override
    public String toString() {
        return "Updateable{" + "size=" + collection.size() + '}';
    }
}
