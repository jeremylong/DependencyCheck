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
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.update;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeMap;
import org.owasp.dependencycheck.utils.DownloadFailedException;
import org.owasp.dependencycheck.utils.Downloader;

/**
 * Contains a collection of updateable NvdCveInfo objects. This is used to
 * determine which files need to be downloaded and processed.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class UpdateableNvdCve implements java.lang.Iterable<NvdCveInfo>, Iterator<NvdCveInfo> {

    /**
     * A collection of sources of data.
     */
    private Map<String, NvdCveInfo> collection = new TreeMap<String, NvdCveInfo>();

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
     * @throws MalformedURLException thrown if the URL provided is invalid
     * @throws DownloadFailedException thrown if the download fails.
     */
    public void add(String id, String url, String oldUrl) throws MalformedURLException, DownloadFailedException {
        add(id, url, oldUrl, false);
    }

    /**
     * Adds a new entry of updateable information to the contained collection.
     *
     * @param id the key for the item to be added
     * @param url the URL to download the item
     * @param oldUrl the URL for the old version of the item (the NVD CVE old
     * schema still contains useful data we need).
     * @param needsUpdate whether or not the data needs to be updated
     * @throws MalformedURLException thrown if the URL provided is invalid
     * @throws DownloadFailedException thrown if the download fails.
     */
    public void add(String id, String url, String oldUrl, boolean needsUpdate) throws MalformedURLException, DownloadFailedException {
        final NvdCveInfo item = new NvdCveInfo();
        item.setNeedsUpdate(needsUpdate); //the others default to true, to make life easier later this should default to false.
        item.setId(id);
        item.setUrl(url);
        item.setOldSchemaVersionUrl(oldUrl);
        item.setTimestamp(Downloader.getLastModified(new URL(url)));
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
     * An internal iterator used to implement iterable.
     */
    private Iterator<Entry<String, NvdCveInfo>> iterableContent = null;

    /**
     * <p>Returns an iterator for the NvdCveInfo contained.</p>
     * <p><b>This method is not thread safe.</b></p>
     *
     * @return an NvdCveInfo Iterator
     */
    @Override
    public Iterator<NvdCveInfo> iterator() {
        iterableContent = collection.entrySet().iterator();
        return this;
    }

    /**
     * <p>Returns whether or not there is another item in the collection.</p>
     * <p><b>This method is not thread safe.</b></p>
     *
     * @return true or false depending on whether or not another item exists in
     * the collection
     */
    @Override
    public boolean hasNext() {
        return iterableContent.hasNext();
    }

    /**
     * <p>Returns the next item in the collection.</p>
     * <p><b>This method is not thread safe.</b></p>
     *
     * @return the next NvdCveInfo item in the collection
     */
    @Override
    public NvdCveInfo next() {
        return iterableContent.next().getValue();
    }

    /**
     * <p>Removes the current NvdCveInfo object from the collection.</p>
     * <p><b>This method is not thread safe.</b></p>
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
    NvdCveInfo get(String key) {
        return collection.get(key);
    }

    @Override
    public String toString() {
        return "Updateable{" + "size=" + collection.size() + '}';
    }
}
