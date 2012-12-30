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
package org.codesecure.dependencycheck.data.nvdcve.xml;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import org.apache.lucene.document.Document;
import org.apache.lucene.document.Field;
import org.apache.lucene.document.StoredField;
import org.apache.lucene.document.StringField;
import org.apache.lucene.index.CorruptIndexException;
import org.apache.lucene.index.Term;
import org.codesecure.dependencycheck.data.lucene.LuceneUtils;
import org.codesecure.dependencycheck.data.nvdcve.generated.VulnerabilityType;
import org.codesecure.dependencycheck.data.nvdcve.Fields;
import org.codesecure.dependencycheck.data.nvdcve.Index;
import org.codesecure.dependencycheck.data.nvdcve.generated.FactRefType;
import org.codesecure.dependencycheck.data.nvdcve.generated.LogicalTest;
import org.codesecure.dependencycheck.data.nvdcve.generated.PlatformType;

/**
 * The Indexer is used to convert a VULNERABLE_CPE Entry, retrieved from the
 * VULNERABLE_CPE XML file, into a Document that is stored in the Lucene index.
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class Indexer extends Index implements EntrySaveDelegate {

    /**
     * Saves an NVD CVE Entry into the Lucene index.
     *
     * @param vulnerability a NVD CVE vulnerability.
     * @throws CorruptIndexException is thrown if the index is corrupt.
     * @throws IOException is thrown if an IOException occurs.
     */
    public void saveEntry(VulnerabilityType vulnerability) throws CorruptIndexException, IOException {
        try {
            Document doc = null;
            try {
                doc = convertEntryToDoc(vulnerability);
            } catch (UnsupportedEncodingException ex) {
                Logger.getLogger(Indexer.class.getName()).log(Level.SEVERE, null, ex);
            }

            if (doc == null) {
                return;
            }

            Term name = new Term(Fields.CVE_ID, LuceneUtils.escapeLuceneQuery(vulnerability.getId()));
            indexWriter.updateDocument(name, doc);
        } catch (JAXBException ex) {
            Logger.getLogger(Indexer.class.getName()).log(Level.SEVERE, "Unable to add " + vulnerability.getId() + " to the Lucene index.", ex);
        }
    }

    /**
     * Converts a VULNERABLE_CPE vulnerability into a Lucene Document.
     *
     * @param vulnerability a VULNERABLE_CPE Entry.
     * @return a Lucene Document containing a VULNERABLE_CPE Entry.
     * @throws JAXBException is thrown when there is a JAXBException.
     * @throws UnsupportedEncodingException if the system doesn't support utf-8
     */
    protected Document convertEntryToDoc(VulnerabilityType vulnerability) throws JAXBException, UnsupportedEncodingException {
        boolean hasApplication = false;
        Document doc = new Document();

        if (vulnerability.getVulnerableConfigurations() != null) {

            for (PlatformType pt : vulnerability.getVulnerableConfigurations()) {
                hasApplication = addVulnerableProducts(doc, pt.getLogicalTest());
            }

        } else if (vulnerability.getVulnerableSoftwareList() != null) { //this should never be reached, but is here just in case.
            for (String cpe : vulnerability.getVulnerableSoftwareList().getProducts()) {
                if (cpe.startsWith("cpe:/a:")) {
                    hasApplication = true;
                    addVulnerableCpe(cpe, doc);
                }
            }
        } else {
            return null;
        }

        //there are no cpe:/a that are vulnerable - don't add it to the index.
        if (!hasApplication) {
            return null;
        }

        Field name = new StringField(Fields.CVE_ID, vulnerability.getId(), Field.Store.NO);
        doc.add(name);

//        Field description = new Field(Fields.DESCRIPTION, vulnerability.getSummary(), Field.Store.NO, Field.Index.ANALYZED);
//        doc.add(description);

        JAXBContext context = JAXBContext.newInstance("org.codesecure.dependencycheck.data.nvdcve.generated");

        Marshaller m = context.createMarshaller();
        m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);

        ByteArrayOutputStream out = new ByteArrayOutputStream();

        m.marshal(vulnerability, out);

        Field xml = new StoredField(Fields.XML, out.toString("UTF-8"));
        doc.add(xml);

        return doc;
    }

    private boolean addVulnerableProducts(Document doc, LogicalTest logicalTest) {
        boolean retVal = false;
        for (LogicalTest lt : logicalTest.getLogicalTests()) {
            retVal = retVal || addVulnerableProducts(doc, lt);
        }
        for (FactRefType facts : logicalTest.getFactReves()) {
            String cpe = facts.getName();
            if (cpe.startsWith("cpe:/a:")) {
                retVal = true;
                addVulnerableCpe(cpe, doc);
            }
        }
        return retVal;
    }

    private void addVulnerableCpe(String cpe, Document doc) {
        Field vulnerable = new StringField(Fields.VULNERABLE_CPE, cpe, Field.Store.NO);
        doc.add(vulnerable);
    }
}
