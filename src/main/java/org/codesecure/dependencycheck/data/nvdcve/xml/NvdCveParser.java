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
        Pattern rxEntry = Pattern.compile("^\\s*\\<entry\\s*id\\=\\\"([^\\\"]+)\\\"");
        Pattern rxEntryEnd = Pattern.compile("^\\s*\\</entry");
        Pattern rxFact = Pattern.compile("^\\s*\\<cpe\\-lang\\:fact\\-ref name=\\\"([^\\\"]+)");
        Pattern rxSummary = Pattern.compile("^\\s*\\<vuln:summary>([^\\<]+");
        try {
            fr = new FileReader(file);
            br = new BufferedReader(fr);
            StringBuilder sb = new StringBuilder(7000);
            String str = null;
            String id = null;
            Document doc = new Document();
            while ((str = br.readLine()) != null) {
                sb.append(str);
                //facts occur more often, do them first.
                Matcher matcherFact = rxFact.matcher(str);
                if (matcherFact.matches()) {
                   addVulnerableCpe(matcherFact.group(0), doc);
                   continue;
                }
                Matcher matcherEntry = rxEntry.matcher(str);
                if (matcherEntry.matches()) {
                    id = matcherEntry.group(0);
                    Field name = new Field(Fields.CVE_ID, id, Field.Store.NO, Field.Index.ANALYZED);
                    name.setIndexOptions(IndexOptions.DOCS_ONLY);
                    doc.add(name);
                    continue;
                }
                Matcher matcherSummary = rxSummary.matcher(str);
                if (matcherSummary.matches()) {
                   String summary = matcherSummary.group(0);
                   Field description = new Field(Fields.DESCRIPTION, summary, Field.Store.NO, Field.Index.ANALYZED);
                   description.setIndexOptions(IndexOptions.DOCS_ONLY);
                   doc.add(description);
                   continue;
                }
                Matcher matcherEntryEnd = rxEntryEnd.matcher(str);
                if (matcherEntryEnd.matches()) {
                    
                    Field xml = new Field(Fields.XML, sb.toString(), Field.Store.YES, Field.Index.NO);
                    doc.add(xml);
                    
                    Term name = new Term(Fields.CVE_ID, LuceneUtils.escapeLuceneQuery(id));
                    indexWriter.updateDocument(name, doc);
                    
                    doc = new Document();
                    
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
