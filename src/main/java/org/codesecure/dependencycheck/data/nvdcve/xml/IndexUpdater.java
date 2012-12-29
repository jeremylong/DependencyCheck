package org.codesecure.dependencycheck.data.nvdcve.xml;
/*
 * This file is part of DependencyCheck.
 *
 * DependencyCheck is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * DependencyCheck is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * DependencyCheck. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import org.codesecure.dependencycheck.data.CachedWebDataSource;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.lucene.index.CorruptIndexException;
import org.codesecure.dependencycheck.data.nvdcve.Index;
import org.codesecure.dependencycheck.data.UpdateException;
import org.codesecure.dependencycheck.utils.DownloadFailedException;
import org.codesecure.dependencycheck.utils.Downloader;
import org.codesecure.dependencycheck.utils.FileUtils;
import org.codesecure.dependencycheck.utils.Settings;

/**
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class IndexUpdater extends Index implements CachedWebDataSource {

    /**
     * The name of the properties file containing the timestamp of the last
     * update.
     */
    private static final String UPDATE_PROPERTIES_FILE = "lastupdated.prop";
    /**
     * The properties file key for the last updated field - used to store the
     * last updated time of the Modified NVD CVE xml file.
     */
    private static final String LAST_UPDATED_MODIFIED = "lastupdated.modified";
    /**
     * Stores the last updated time for each of the NVD CVE files. These
     * timestamps should be updated if we process the modified file within 7
     * days of the last update.
     */
    private static final String LAST_UPDATED_BASE = "lastupdated.";
    /**
     * The current version of the index
     */
    public static final String INDEX_VERSION = "1.1";

    /**
     * <p>Downloads the latest NVD CVE XML file from the web and imports it into
     * the current CVE Index.</p>
     *
     * @throws UpdateException is thrown if there is an error updating the index
     */
    public void update() throws UpdateException {
        try {
            Map<String, NvdCveUrl> update = updateNeeded();
            int maxUpdates = 0;
            for (NvdCveUrl cve : update.values()) {
                if (cve.getNeedsUpdate()) {
                    maxUpdates += 1;
                }
            }
            if (maxUpdates > 3) {
                Logger.getLogger(IndexUpdater.class.getName()).log(Level.WARNING,
                        "NVD CVE requires several updates; this could take a couple of minutes.");
            }
            int count = 0;
            for (NvdCveUrl cve : update.values()) {
                if (cve.getNeedsUpdate()) {
                    count += 1;
                    Logger.getLogger(IndexUpdater.class.getName()).log(Level.WARNING,
                            "Updating NVD CVE ({0} of {1})", new Object[]{count, maxUpdates});
                    URL url = new URL(cve.getUrl());
                    File outputPath = null;
                    try {
                        Logger.getLogger(IndexUpdater.class.getName()).log(Level.WARNING, "Downloading {0}", cve.getUrl());
                        outputPath = File.createTempFile("cve" + cve.getId() + "_", ".xml");
                        Downloader.fetchFile(url, outputPath, false);
                        Logger.getLogger(IndexUpdater.class.getName()).log(Level.WARNING, "Processing {0}", cve.getUrl());
                        importXML(outputPath.toString());
                        Logger.getLogger(IndexUpdater.class.getName()).log(Level.WARNING,
                                "Completed updated {0} of {1}", new Object[]{count, maxUpdates});
                    } catch (FileNotFoundException ex) {
                        //Logger.getLogger(IndexUpdater.class.getName()).log(Level.SEVERE, null, ex);
                        throw new UpdateException(ex);
                    } catch (IOException ex) {
                        //Logger.getLogger(IndexUpdater.class.getName()).log(Level.SEVERE, null, ex);
                        throw new UpdateException(ex);
                    } finally {
                        try {
                            if (outputPath != null && outputPath.exists()) {
                                outputPath.delete();
                            }
                        } finally {
                            if (outputPath != null && outputPath.exists()) {
                                outputPath.deleteOnExit();
                            }
                        }
                    }
                }
            }
            if (maxUpdates >= 1) {
                writeLastUpdatedPropertyFile(update);
            }
        } catch (MalformedURLException ex) {
            //Logger.getLogger(IndexUpdater.class.getName()).log(Level.SEVERE, null, ex);
            throw new UpdateException(ex);
        } catch (DownloadFailedException ex) {
            //Logger.getLogger(IndexUpdater.class.getName()).log(Level.SEVERE, null, ex);
            throw new UpdateException(ex);
        }
    }

    /**
     * Imports the NVD CVE XML File into the Lucene Index.
     *
     * @param file containing the path to the NVD CVE XML file.
     */
    private void importXML(File file) {
        if (!file.exists()) {
            file.mkdirs();
        }
        NvdCveParser indexer = null;
        org.codesecure.dependencycheck.data.cpe.xml.Indexer cpeIndexer = null;
        try {
            indexer = new NvdCveParser();
            indexer.openIndexWriter();

            //HACK - hack to ensure all CPE data is stored in the index.
            cpeIndexer = new org.codesecure.dependencycheck.data.cpe.xml.Indexer();
            cpeIndexer.openIndexWriter();
            indexer.setCPEIndexer(cpeIndexer);

            indexer.parse(file);
        } catch (CorruptIndexException ex) {
            Logger.getLogger(IndexUpdater.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(IndexUpdater.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            if (indexer != null) {
                indexer.close();
            }
            if (cpeIndexer != null) {
                cpeIndexer.close();
            }
        }
    }
//    public static void importXML(File file) throws FileNotFoundException, IOException, JAXBException,
//            ParserConfigurationException, SAXException {
//
//        SAXParserFactory factory = SAXParserFactory.newInstance();
//        factory.setNamespaceAware(true);
//        XMLReader reader = factory.newSAXParser().getXMLReader();
//
//        JAXBContext context = JAXBContext.newInstance("org.codesecure.dependencycheck.data.nvdcve.generated");
//        NvdCveXmlFilter filter = new NvdCveXmlFilter(context);
//
//        Indexer indexer = new Indexer();
//        indexer.openIndexWriter();
//
//        filter.registerSaveDelegate(indexer);
//
//        reader.setContentHandler(filter);
//        Reader fileReader = new FileReader(file);
//        InputSource is = new InputSource(fileReader);
//        try {
//            reader.parse(is);
//        } catch (IOException ex) {
//            Logger.getLogger(Importer.class.getName()).log(Level.SEVERE, null, ex);
//        } catch (SAXException ex) {
//            Logger.getLogger(Importer.class.getName()).log(Level.SEVERE, null, ex);
//        } finally {
//            indexer.close();
//        }
//    }

    /**
     * Imports the CPE XML File into the Lucene Index.
     *
     * @param path the path to the CPE XML file.
     */
    private void importXML(String path) {
        File f = new File(path);
        importXML(f);
    }

    /**
     * Writes a properties file containing the last updated date to the
     * VULNERABLE_CPE directory.
     *
     * @param timeStamp the timestamp to write.
     */
    private void writeLastUpdatedPropertyFile(Map<String, NvdCveUrl> updated) throws UpdateException {
        String dir;
        try {
            dir = getDataDirectory().getCanonicalPath();
        } catch (IOException ex) {
            Logger.getLogger(IndexUpdater.class.getName()).log(Level.SEVERE, null, ex);
            throw new UpdateException("Unable to locate last updated properties file.", ex);
        }
        File cveProp = new File(dir + File.separatorChar + UPDATE_PROPERTIES_FILE);
        Properties prop = new Properties();
        prop.put("version", INDEX_VERSION);
        for (NvdCveUrl cve : updated.values()) {
            prop.put(LAST_UPDATED_BASE + cve.id, String.valueOf(cve.getTimestamp()));
        }

        OutputStream os = null;
        try {
            os = new FileOutputStream(cveProp);
            OutputStreamWriter out = new OutputStreamWriter(os, "UTF-8");
            prop.store(out, dir);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(IndexUpdater.class.getName()).log(Level.SEVERE, null, ex);
            throw new UpdateException("Unable to find last updated properties file.", ex);
        } catch (IOException ex) {
            Logger.getLogger(IndexUpdater.class.getName()).log(Level.SEVERE, null, ex);
            throw new UpdateException("Unable to update last updated properties file.", ex);
        } finally {
            if (os != null) {
                try {
                    os.flush();
                } catch (IOException ex) {
                    Logger.getLogger(IndexUpdater.class.getName()).log(Level.SEVERE, null, ex);
                }
                try {
                    os.close();
                } catch (IOException ex) {
                    Logger.getLogger(IndexUpdater.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        }
    }

    /**
     * Determines if the index needs to be updated. This is done by fetching the
     * nvd cve meta data and checking the last update date. If the data needs to
     * be refreshed this method will return the NvdCveUrl for the files that
     * need to be updated.
     *
     * @return the NvdCveUrl of the files that need to be updated.
     * @throws MalformedURLException is thrown if the URL for the NVD CVE Meta
     * data is incorrect.
     * @throws DownloadFailedException is thrown if there is an error.
     * downloading the nvd cve download data file.
     * @throws UpdateException Is thrown if there is an issue with the last updated properties file.
     */
    public Map<String, NvdCveUrl> updateNeeded() throws MalformedURLException, DownloadFailedException, UpdateException {

        Map<String, NvdCveUrl> currentlyPublished;
        try {
            currentlyPublished = retrieveCurrentTimestampsFromWeb();
        } catch (InvalidDataException ex) {
            Logger.getLogger(IndexUpdater.class.getName()).log(Level.SEVERE, null, ex);
            throw new DownloadFailedException("Unable to retrieve valid timestamp from nvd cve downloads page", ex);
        }
        if (currentlyPublished == null) {
            throw new DownloadFailedException("Unable to retrieve valid timestamp from nvd cve downloads page");
        }
        String dir;
        try {
            dir = getDataDirectory().getCanonicalPath();
        } catch (IOException ex) {
            Logger.getLogger(IndexUpdater.class.getName()).log(Level.SEVERE, null, ex);
            throw new UpdateException("Unable to locate last updated properties file.", ex);
        }

        File f = new File(dir);
        if (f.exists()) {
            File cveProp = new File(dir + File.separatorChar + UPDATE_PROPERTIES_FILE);
            if (cveProp.exists()) {
                Properties prop = new Properties();
                InputStream is = null;
                try {
                    is = new FileInputStream(cveProp);
                    prop.load(is);

                    boolean deleteAndRecreate = false;
                    float version = 0;

                    if (prop.getProperty("version") == null) {
                        deleteAndRecreate = true;
                    } else {
                        try {
                            version = Float.parseFloat(prop.getProperty("version"));
                            float currentVersion = Float.parseFloat(INDEX_VERSION);
                            if (currentVersion > version) {
                                deleteAndRecreate = true;
                            }
                        } catch (NumberFormatException ex) {
                            deleteAndRecreate = true;
                        }
                    }
                    if (deleteAndRecreate) {
                        Logger.getLogger(IndexUpdater.class.getName()).log(Level.WARNING, "Index version is old. Rebuilding the index.");
                        is.close();
                        //this is an old version of the lucene index - just delete it
                        FileUtils.delete(f);

                        //this importer also updates the CPE index and it is also using an old version
                        org.codesecure.dependencycheck.data.cpe.Index cpeidx = new org.codesecure.dependencycheck.data.cpe.Index();
                        File cpeDir = cpeidx.getDataDirectory();
                        FileUtils.delete(cpeDir);
                        return currentlyPublished;
                    }

                    long lastUpdated = Long.parseLong(prop.getProperty(LAST_UPDATED_MODIFIED));
                    Date now = new Date();
                    int days = Settings.getInt(Settings.KEYS.CVE_MODIFIED_VALID_FOR_DAYS);
                    int maxEntries = Settings.getInt(Settings.KEYS.CVE_URL_COUNT);
                    if (lastUpdated == currentlyPublished.get("modified").timestamp) {
                        currentlyPublished.clear(); //we don't need to update anything.
                    } else if (withinRange(lastUpdated, now.getTime(), days)) {
                        currentlyPublished.get("modified").setNeedsUpdate(true);
                        for (int i = 1; i <= maxEntries; i++) {
                            currentlyPublished.get(String.valueOf(i)).setNeedsUpdate(false);
                        }
                    } else { //we figure out which of the several XML files need to be downloaded.
                        currentlyPublished.get("modified").setNeedsUpdate(false);
                        for (int i = 1; i <= maxEntries; i++) {
                            NvdCveUrl cve = currentlyPublished.get(String.valueOf(i));
                            long currentTimestamp = 0;
                            try {
                                currentTimestamp = Long.parseLong(prop.getProperty(LAST_UPDATED_BASE + String.valueOf(i), "0"));
                            } catch (NumberFormatException ex) {
                                Logger.getLogger(IndexUpdater.class.getName()).log(Level.FINEST, "Error parsing " + LAST_UPDATED_BASE
                                        + String.valueOf(i) + " from nvdcve.lastupdated", ex);
                            }
                            if (currentTimestamp == cve.getTimestamp()) {
                                cve.setNeedsUpdate(false); //they default to true.
                            }
                        }
                    }
                } catch (FileNotFoundException ex) {
                    Logger.getLogger(IndexUpdater.class.getName()).log(Level.FINEST, null, ex);
                } catch (IOException ex) {
                    Logger.getLogger(IndexUpdater.class.getName()).log(Level.FINEST, null, ex);
                } catch (NumberFormatException ex) {
                    Logger.getLogger(IndexUpdater.class.getName()).log(Level.FINEST, null, ex);
                } finally {
                    if (is != null) {
                        try {
                            is.close();
                        } catch (IOException ex) {
                            Logger.getLogger(IndexUpdater.class.getName()).log(Level.SEVERE, null, ex);
                        }
                    }
                }
            }
        }
        return currentlyPublished;
    }

    /**
     * Determines if the epoch date is within the range specified of the
     * compareTo epoch time. This takes the (compareTo-date)/1000/60/60/24 to
     * get the number of days. If the calculated days is less then the range the
     * date is considered valid.
     *
     * @param date the date to be checked.
     * @param compareTo the date to compare to.
     * @param range the range in days to be considered valid.
     * @return whether or not the date is within the range.
     */
    private boolean withinRange(long date, long compareTo, int range) {
        double differenceInDays = (compareTo - date) / 1000 / 60 / 60 / 24;
        return differenceInDays < range;
    }

    /**
     * Retrieves the timestamps from the NVD CVE meta data file.
     *
     * @return the timestamp from the currently published nvdcve downloads page
     * @throws MalformedURLException is thrown if the URL for the NVD CCE Meta
     * data is incorrect.
     * @throws DownloadFailedException is thrown if there is an error
     * downloading the nvd cve meta data file
     * @throws InvalidDataException is thrown if there is an exception parsing
     * the timestamps
     */
    protected Map<String, NvdCveUrl> retrieveCurrentTimestampsFromWeb() throws MalformedURLException, DownloadFailedException, InvalidDataException {
        Map<String, NvdCveUrl> map = new HashMap<String, NvdCveUrl>();

        File tmp = null;
        try {
            tmp = File.createTempFile("cve", "meta");
            URL url = new URL(Settings.getString(Settings.KEYS.CVE_META_URL));
            Downloader.fetchFile(url, tmp);
            String html = readFile(tmp);

            String retrieveUrl = Settings.getString(Settings.KEYS.CVE_MODIFIED_URL);
            NvdCveUrl cve = createNvdCveUrl("modified", retrieveUrl, html);
            cve.setNeedsUpdate(false); //the others default to true, to make life easier later this should default to false.
            map.put("modified", cve);
            int max = Settings.getInt(Settings.KEYS.CVE_URL_COUNT);
            for (int i = 1; i <= max; i++) {
                retrieveUrl = Settings.getString(Settings.KEYS.CVE_BASE_URL + i);
                String key = Integer.toString(i);
                cve = createNvdCveUrl(key, retrieveUrl, html);
                map.put(key, cve);
            }
        } catch (IOException ex) {
            throw new DownloadFailedException("Unable to create temporary file for NVD CVE Meta File download.", ex);
        } finally {
            try {
                if (tmp != null && tmp.exists()) {
                    tmp.delete();
                }
            } finally {
                if (tmp != null && tmp.exists()) {
                    tmp.deleteOnExit();
                }
            }
        }
        return map;
    }

    /**
     * Creates a new NvdCveUrl object from the provide id, url, and text/html
     * from the NVD CVE downloads page.
     *
     * @param id the name of this NVD CVE Url
     * @param retrieveUrl the URL to download the file from
     * @param text a bit of HTML from the NVD CVE downloads page that contains
     * the URL and the last updated timestamp.
     * @return a shiny new NvdCveUrl object.
     * @throws InvalidDataException is thrown if the timestamp could not be
     * extracted from the provided text.
     */
    private NvdCveUrl createNvdCveUrl(String id, String retrieveUrl, String text) throws InvalidDataException {
        Pattern pattern = Pattern.compile(Pattern.quote(retrieveUrl) + ".+?\\<br");
        Matcher m = pattern.matcher(text);
        NvdCveUrl item = new NvdCveUrl();
        item.id = id;
        item.url = retrieveUrl;
        if (m.find()) {
            String line = m.group();
            int pos = line.indexOf("Updated:");
            if (pos > 0) {
                pos += 9;
                try {
                    String timestampstr = line.substring(pos, line.length() - 3).replace("at ", "");
                    long timestamp = getEpochTimeFromDateTime(timestampstr);
                    item.setTimestamp(timestamp);
                } catch (NumberFormatException ex) {
                    throw new InvalidDataException("NVD CVE Meta file does not contain a valid timestamp for '" + retrieveUrl + "'.", ex);
                }
            } else {
                throw new InvalidDataException("NVD CVE Meta file does not contain the updated timestamp for '" + retrieveUrl + "'.");
            }
        } else {
            throw new InvalidDataException("NVD CVE Meta file does not contain the url for '" + retrieveUrl + "'.");
        }
        return item;
    }

    /**
     * Parses a timestamp in the format of "MM/dd/yy hh:mm" into a calendar
     * object and returns the epoch time. Note, this removes the millisecond
     * portion of the epoch time so all numbers returned should end in 000.
     *
     * @param timestamp a string in the format of "MM/dd/yy hh:mm"
     * @return a Calendar object.
     * @throws NumberFormatException if the timestamp was parsed incorrectly.
     */
    private long getEpochTimeFromDateTime(String timestamp) throws NumberFormatException {
        Calendar c = new GregorianCalendar();
        int month = Integer.parseInt(timestamp.substring(0, 2));
        int date = Integer.parseInt(timestamp.substring(3, 5));
        int year = 2000 + Integer.parseInt(timestamp.substring(6, 8));
        int hourOfDay = Integer.parseInt(timestamp.substring(9, 11));
        int minute = Integer.parseInt(timestamp.substring(12, 14));
        c.set(year, month, date, hourOfDay, minute, 0);
        long t = c.getTimeInMillis();
        t = (t / 1000) * 1000;
        return t;
    }

    /**
     * Reads a file into a string.
     *
     * @param file the file to be read.
     * @return the contents of the file.
     * @throws IOException is thrown if an IOExcpetion occurs.
     */
    private String readFile(File file) throws IOException {
        InputStreamReader stream = new InputStreamReader(new FileInputStream(file), "UTF-8");
        StringBuilder str = new StringBuilder((int) file.length());
        try {
            char[] buf = new char[8096];
            int read = stream.read(buf, 0, 8096);
            while (read > 0) {
                str.append(buf, 0, read);
                read = stream.read(buf, 0, 8096);
            }
        } finally {
            stream.close();
        }
        return str.toString();
    }

    /**
     * A pojo that contains the Url and timestamp of the current NvdCve XML
     * files.
     */
    protected class NvdCveUrl {

        /**
         * an id.
         */
        private String id;

        /**
         * Get the value of id
         *
         * @return the value of id
         */
        public String getId() {
            return id;
        }

        /**
         * Set the value of id
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
         * Get the value of url
         *
         * @return the value of url
         */
        public String getUrl() {
            return url;
        }

        /**
         * Set the value of url
         *
         * @param url new value of url
         */
        public void setUrl(String url) {
            this.url = url;
        }
        /**
         * a timestamp - epoch time.
         */
        private long timestamp;

        /**
         * Get the value of timestamp - epoch time
         *
         * @return the value of timestamp - epoch time
         */
        public long getTimestamp() {
            return timestamp;
        }

        /**
         * Set the value of timestamp - epoch time
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
         * Get the value of needsUpdate
         *
         * @return the value of needsUpdate
         */
        public boolean getNeedsUpdate() {
            return needsUpdate;
        }

        /**
         * Set the value of needsUpdate
         *
         * @param needsUpdate new value of needsUpdate
         */
        public void setNeedsUpdate(boolean needsUpdate) {
            this.needsUpdate = needsUpdate;
        }
    }
}
