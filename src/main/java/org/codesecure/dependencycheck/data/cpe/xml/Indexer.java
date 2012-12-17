package org.codesecure.dependencycheck.data.cpe.xml;
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

import java.io.IOException;
import org.apache.lucene.document.Document;
import org.apache.lucene.document.Field;
import org.apache.lucene.document.StoredField;
import org.apache.lucene.document.TextField;
import org.apache.lucene.index.CorruptIndexException;
import org.apache.lucene.index.FieldInfo.IndexOptions;
import org.apache.lucene.index.Term;
import org.codesecure.dependencycheck.data.cpe.Entry;
import org.codesecure.dependencycheck.data.cpe.Fields;
import org.codesecure.dependencycheck.data.cpe.Index;

/**
 * The Indexer is used to convert a CPE Entry, retrieved from the CPE XML file,
 * into a Document that is stored in the Lucene index.
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class Indexer extends Index implements EntrySaveDelegate {

    /**
     * Saves a CPE Entry into the Lucene index.
     *
     * @param entry a CPE entry.
     * @throws CorruptIndexException is thrown if the index is corrupt.
     * @throws IOException is thrown if an IOException occurs.
     */
    public void saveEntry(Entry entry) throws CorruptIndexException, IOException {
        Document doc = convertEntryToDoc(entry);
        //Term term = new Term(Fields.NVDID, LuceneUtils.escapeLuceneQuery(entry.getNvdId()));
        Term term = new Term(Fields.NAME, entry.getName());
        indexWriter.updateDocument(term, doc);
    }

    /**
     * Converts a CPE entry into a Lucene Document.
     *
     * @param entry a CPE Entry.
     * @return a Lucene Document containing a CPE Entry.
     */
    protected Document convertEntryToDoc(Entry entry) {
        Document doc = new Document();

        Field name = new StoredField(Fields.NAME, entry.getName());
        doc.add(name);

        Field vendor = new TextField(Fields.VENDOR, entry.getVendor(), Field.Store.NO);
        vendor.setBoost(5.0F);
        doc.add(vendor);

        Field product = new TextField(Fields.PRODUCT, entry.getProduct(), Field.Store.NO);
        product.setBoost(5.0F);
        doc.add(product);

        //TODO revision should likely be its own field
        if (entry.getVersion() != null) {
            Field version = null;
            if (entry.getRevision() != null) {
                version = new TextField(Fields.VERSION, entry.getVersion() + " "
                        + entry.getRevision(), Field.Store.NO);
            } else {
                version = new TextField(Fields.VERSION, entry.getVersion(),
                        Field.Store.NO);
            }
            version.setBoost(0.8F);
            doc.add(version);
        }
        return doc;
    }
}
