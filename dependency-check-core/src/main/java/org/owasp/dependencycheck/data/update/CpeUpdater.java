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
 * Copyright (c) 2015 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.update;
/*
import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import static org.owasp.dependencycheck.data.nvdcve.DatabaseProperties.LAST_CPE_UPDATE;
import org.owasp.dependencycheck.data.update.cpe.CPEHandler;
import org.owasp.dependencycheck.data.update.cpe.Cpe;
import org.owasp.dependencycheck.data.update.exception.UpdateException;
import org.owasp.dependencycheck.utils.DateUtil;
import org.owasp.dependencycheck.utils.DownloadFailedException;
import org.owasp.dependencycheck.utils.Downloader;
import org.owasp.dependencycheck.utils.ExtractionUtil;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.XmlUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.SAXException;
*/
/**
 *
 * This class is currently unused and if enabled will likely not work on MySQL
 * as the MERGE statement is used.
 *
 * The CpeUpdater is designed to download the CPE data file from NIST and import
 * the data into the database. However, as this currently adds no beneficial
 * data, compared to what is in the CPE data contained in the CVE data files,
 * this class is not currently used. The code is being kept as a future update
 * may utilize more data from the CPE XML files.
 *
 * @deprecated the CPE updater is not currently used.
 * @author Jeremy Long
 */
@Deprecated
public class CpeUpdater { //extends BaseUpdater implements CachedWebDataSource {
//
//    /**
//     * Static logger.
//     */
//    private static final Logger LOGGER = LoggerFactory.getLogger(CpeUpdater.class);
//
//    @Override
//    public void update() throws UpdateException {
//        /*
//        //the following could be used if this were ever used.
//        try {
//            if (!Settings.getBoolean(Settings.KEYS.UPDATE_NVDCVE_ENABLED, true)) {
//                return;
//            }
//        } catch (InvalidSettingException ex) {
//            LOGGER.trace("invalid setting UPDATE_NVDCVE_ENABLED", ex);
//        }
//         */
//
//        try {
//            openDataStores();
//            if (updateNeeded()) {
//                LOGGER.info("Updating the Common Platform Enumeration (CPE)");
//                final File xml = downloadCpe();
//                final List<Cpe> cpes = processXML(xml);
//                getCveDB().deleteUnusedCpe();
//                for (Cpe cpe : cpes) {
//                    getCveDB().addCpe(cpe.getValue(), cpe.getVendor(), cpe.getProduct());
//                }
//                final long now = System.currentTimeMillis();
//                getProperties().save(LAST_CPE_UPDATE, Long.toString(now));
//                LOGGER.info("CPE update complete");
//            }
//        } finally {
//            closeDataStores();
//        }
//    }
//
//    /**
//     * Downloads the CPE XML file.
//     *
//     * @return the file reference to the CPE.xml file
//     * @throws UpdateException thrown if there is an issue downloading the XML
//     * file
//     */
//    private File downloadCpe() throws UpdateException {
//        File xml;
//        final URL url;
//        try {
//            url = new URL(Settings.getString(Settings.KEYS.CPE_URL));
//            xml = File.createTempFile("cpe", ".xml", Settings.getTempDirectory());
//            Downloader.fetchFile(url, xml);
//            if (url.toExternalForm().endsWith(".xml.gz")) {
//                ExtractionUtil.extractGzip(xml);
//            }
//
//        } catch (MalformedURLException ex) {
//            throw new UpdateException("Invalid CPE URL", ex);
//        } catch (DownloadFailedException ex) {
//            throw new UpdateException("Unable to download CPE XML file", ex);
//        } catch (IOException ex) {
//            throw new UpdateException("Unable to create temporary file to download CPE", ex);
//        }
//        return xml;
//    }
//
//    /**
//     * Parses the CPE XML file to return a list of CPE entries.
//     *
//     * @param xml the CPE data file
//     * @return the list of CPE entries
//     * @throws UpdateException thrown if there is an issue with parsing the XML
//     * file
//     */
//    private List<Cpe> processXML(final File xml) throws UpdateException {
//        try {
//            final SAXParser saxParser = XmlUtils.buildSecureSaxParser();
//            final CPEHandler handler = new CPEHandler();
//            saxParser.parse(xml, handler);
//            return handler.getData();
//        } catch (ParserConfigurationException ex) {
//            throw new UpdateException("Unable to parse CPE XML file due to SAX Parser Issue", ex);
//        } catch (SAXException ex) {
//            throw new UpdateException("Unable to parse CPE XML file due to SAX Parser Exception", ex);
//        } catch (IOException ex) {
//            throw new UpdateException("Unable to parse CPE XML file due to IO Failure", ex);
//        }
//    }
//
//    /**
//     * Checks to find the last time the CPE data was refreshed and if it needs
//     * to be updated.
//     *
//     * @return true if the CPE data should be refreshed
//     */
//    private boolean updateNeeded() {
//        final long now = System.currentTimeMillis();
//        final int days = Settings.getInt(Settings.KEYS.CPE_MODIFIED_VALID_FOR_DAYS, 30);
//        long timestamp = 0;
//        final String ts = getProperties().getProperty(LAST_CPE_UPDATE);
//        if (ts != null && ts.matches("^[0-9]+$")) {
//            timestamp = Long.parseLong(ts);
//        }
//        return !DateUtil.withinDateRange(timestamp, now, days);
//    }
}
