/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.codesecure.dependencycheck.data.nvdcve.xml;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.lucene.document.Document;
import org.apache.lucene.document.Field;
import org.apache.lucene.index.FieldInfo.IndexOptions;
import org.apache.lucene.index.Term;
import org.codesecure.dependencycheck.data.lucene.LuceneUtils;
import org.codesecure.dependencycheck.data.nvdcve.Fields;
import org.codesecure.dependencycheck.data.nvdcve.Index;

/**
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class NvdCveParser extends Index {
 
    public void parse(File file) {
        FileReader fr = null;
        BufferedReader br = null;
        Pattern rxEntry = Pattern.compile("^\\s*<entry\\s*id\\=\\\"([^\\\"]+)\\\".*$");
        Pattern rxEntryEnd = Pattern.compile("^\\s*</entry>.*$");
        Pattern rxFact = Pattern.compile("^\\s*<cpe\\-lang\\:fact\\-ref name=\\\"([^\\\"]+).*$");
        Pattern rxSummary = Pattern.compile("^\\s*<vuln:summary>([^\\<]+).*$");
        try {
            fr = new FileReader(file);
            br = new BufferedReader(fr);
            StringBuilder sb = new StringBuilder(7000);
            String str = null;
            String id = null;
            Document doc = new Document();
            boolean skipEntry = true;
            boolean started = false;
            
            while ((str = br.readLine()) != null) {
                Matcher matcherEntryEnd = rxEntryEnd.matcher(str);
                
                if (started && !matcherEntryEnd.matches()) {
                    sb.append(str);
                }
                //facts occur more often, do them first.
                Matcher matcherFact = rxFact.matcher(str);
                if (matcherFact.matches()) {
                    String cpe = matcherFact.group(1);
                    if (cpe != null && cpe.startsWith("cpe:/a:")) {
                        skipEntry = false;
                        addVulnerableCpe(cpe, doc);
                    }
                   continue;
                }
                Matcher matcherEntry = rxEntry.matcher(str);
                if (matcherEntry.matches()) {
                    started = true;
                    id = matcherEntry.group(1);
                    
                    sb.append("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>");
                    sb.append("<vulnerabilityType xmlns=\"http://scap.nist.gov/schema/vulnerability/0.4\" xmlns:vuln=\"http://scap.nist.gov/schema/vulnerability/0.4\"  xmlns:cpe-lang=\"http://cpe.mitre.org/language/2.0\" xmlns:cvss=\"http://scap.nist.gov/schema/cvss-v2/0.2\" xmlns:scap-core=\"http://scap.nist.gov/schema/scap-core/0.1\" xmlns:patch=\"http://scap.nist.gov/schema/patch/0.1\" xmlns:ns6=\"http://scap.nist.gov/schema/cve/0.1\" xmlns:cce=\"http://scap.nist.gov/schema/cce/0.1\" xmlns:vulnerability=\"http://scap.nist.gov/schema/feed/vulnerability/2.0\"");
                    sb.append(" id=\"").append(id).append("\">");
                    //sb.append(str); //need to do the above to get the correct schema generated from files.
                    
                    Field name = new Field(Fields.CVE_ID, id, Field.Store.NO, Field.Index.ANALYZED);
                    name.setIndexOptions(IndexOptions.DOCS_ONLY);
                    doc.add(name);
                    continue;
                }
                Matcher matcherSummary = rxSummary.matcher(str);
                if (matcherSummary.matches()) {
                   String summary = matcherSummary.group(1);
                   Field description = new Field(Fields.DESCRIPTION, summary, Field.Store.NO, Field.Index.ANALYZED);
                   description.setIndexOptions(IndexOptions.DOCS_ONLY);
                   doc.add(description);
                   continue;
                }
                
                if (matcherEntryEnd.matches()) {
                    sb.append("</vulnerabilityType>");
                    Field xml = new Field(Fields.XML, sb.toString(), Field.Store.YES, Field.Index.NO);
                    doc.add(xml);
                    
                    if (!skipEntry) {
                        Term name = new Term(Fields.CVE_ID, id);
                        indexWriter.deleteDocuments(name);
                        indexWriter.addDocument(doc);
                        //indexWriter.updateDocument(name, doc);
                    }
                    //reset the document
                    doc = new Document();
                    sb = new StringBuilder(7000);
                    id = null;
                    skipEntry = true;
                    started = false;
                }
            }
            
            
        } catch (FileNotFoundException ex) {
            Logger.getLogger(NvdCveParser.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(NvdCveParser.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                fr.close();
            } catch (IOException ex) {
                Logger.getLogger(NvdCveParser.class.getName()).log(Level.SEVERE, null, ex);
            }
            try {
                if (br != null) {
                    br.close();
                }
            } catch (IOException ex) {
                Logger.getLogger(NvdCveParser.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }
    
    
    private void addVulnerableCpe(String cpe, Document doc) {
        Field vulnerable = new Field(Fields.VULNERABLE_CPE, cpe, Field.Store.NO, Field.Index.ANALYZED);
        vulnerable.setIndexOptions(IndexOptions.DOCS_ONLY);
        doc.add(vulnerable);
    }
}
