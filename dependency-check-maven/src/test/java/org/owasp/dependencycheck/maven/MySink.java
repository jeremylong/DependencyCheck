/*
 * This file is part of dependency-check-maven.
 *
 * Dependency-check-maven is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-check-maven is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * dependency-check-maven. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.maven;

import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.maven.doxia.logging.Log;
import org.apache.maven.doxia.sink.Sink;
import org.apache.maven.doxia.sink.SinkEventAttributes;

/**
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class MySink implements Sink {

    private OutputStreamWriter out = null;

    public MySink(OutputStream os) {
        out = new OutputStreamWriter(os);

    }

    private void writeTag(String tag) {
        try {
            out.write(tag);
        } catch (IOException ex) {
            Logger.getLogger(MySink.class.getName()).log(Level.SEVERE, "Error writing a tag; unable to generate the report");
            Logger.getLogger(MySink.class.getName()).log(Level.FINE, null, ex);
        }
    }

    public void head() {
        writeTag("<head>");
    }

    public void head_() {
        writeTag("</head>");
    }

    public void title() {
        writeTag("<title>");
    }

    public void title_() {
        writeTag("</title>");
    }

    public void author() {
        writeTag("<author>");
    }

    public void author_() {
        writeTag("</author>");
    }

    public void date() {
        writeTag("<time>");
    }

    public void date_() {
        writeTag("</time>");
    }

    public void body() {
        writeTag("<body>");
    }

    public void body_() {
        writeTag("</body>");
    }

    public void sectionTitle() {
        writeTag("<h1>");
    }

    public void sectionTitle_() {
        writeTag("</h1>");
    }

    public void section1() {
        writeTag("<div>");
    }

    public void section1_() {
        writeTag("</div>");
    }

    public void sectionTitle1() {
        writeTag("<h2>");
    }

    public void sectionTitle1_() {
        writeTag("</h2>");
    }

    public void section2() {
        writeTag("<div>");
    }

    public void section2_() {
        writeTag("</div>");
    }

    public void sectionTitle2() {
        writeTag("<h3>");
    }

    public void sectionTitle2_() {
        writeTag("</h3>");
    }

    public void section3() {
        writeTag("<div>");
    }

    public void section3_() {
        writeTag("</div>");
    }

    public void sectionTitle3() {
        writeTag("<h4>");
    }

    public void sectionTitle3_() {
        writeTag("</h4>");
    }

    public void section4() {
        writeTag("<div>");
    }

    public void section4_() {
        writeTag("</div>");
    }

    public void sectionTitle4() {
        writeTag("<h5>");
    }

    public void sectionTitle4_() {
        writeTag("</h5>");
    }

    public void section5() {
        writeTag("<div>");
    }

    public void section5_() {
        writeTag("</div>");
    }

    public void sectionTitle5() {
        writeTag("<h6>");
    }

    public void sectionTitle5_() {
        writeTag("</h6>");
    }

    public void list() {
        writeTag("<ul>");
    }

    public void list_() {
        writeTag("</ul>");
    }

    public void listItem() {
        writeTag("<li>");
    }

    public void listItem_() {
        writeTag("</li>");
    }

    public void numberedList(int numbering) {
        writeTag("<ol>");
    }

    public void numberedList_() {
        writeTag("</ol>");
    }

    public void numberedListItem() {
        writeTag("<li>");
    }

    public void numberedListItem_() {
        writeTag("</li>");
    }

    public void definitionList() {
        writeTag("<dl>");
    }

    public void definitionList_() {
        writeTag("</dl>");
    }

    public void definitionListItem() {
        writeTag("<dt>");
    }

    public void definitionListItem_() {
        writeTag("</dt>");
    }

    public void definition() {
        writeTag("<dd>");
    }

    public void definition_() {
        writeTag("</dd>");
    }

    public void definedTerm() {
        writeTag("<dt>");
    }

    public void definedTerm_() {
        writeTag("</dt>");
    }

    public void figure() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public void figure_() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public void figureCaption() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public void figureCaption_() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public void figureGraphics(String name) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public void table() {
        writeTag("<table>");
    }

    public void table_() {
        writeTag("</table>");
    }

    public void tableRows(int[] justification, boolean grid) {
        writeTag("<tr>");
    }

    public void tableRows_() {
        writeTag("</tr>");
    }

    public void tableRow() {
        writeTag("<tr>");
    }

    public void tableRow_() {
        writeTag("</tr>");
    }

    public void tableCell() {
        writeTag("<td>");
    }

    public void tableCell(String width) {
        writeTag("<td>");
    }

    public void tableCell_() {
        writeTag("</td>");
    }

    public void tableHeaderCell() {
        writeTag("<th>");
    }

    public void tableHeaderCell(String width) {
        writeTag("<th>");
    }

    public void tableHeaderCell_() {
        writeTag("</th>");
    }

    public void tableCaption() {
        writeTag("<caption>");
    }

    public void tableCaption_() {
        writeTag("</caption>");
    }

    public void paragraph() {
        writeTag("<p>");
    }

    public void paragraph_() {
        writeTag("</p>");
    }

    public void verbatim(boolean boxed) {
        writeTag("<pre>");
    }

    public void verbatim_() {
        writeTag("</pre>");
    }

    public void horizontalRule() {
        writeTag("<hr/>");
    }

    public void pageBreak() {
        writeTag("<br/>");
    }

    public void anchor(String name) {
        writeTag("<a href=\"" + name + "\">");
    }

    public void anchor_() {
        writeTag("</a>");
    }

    public void link(String name) {
        writeTag("<link href=\"" + name + "\">");
    }

    public void link_() {
        writeTag("</link>");
    }

    public void italic() {
        writeTag("<i>");
    }

    public void italic_() {
        writeTag("</i>");
    }

    public void bold() {
        writeTag("<b>");
    }

    public void bold_() {
        writeTag("</b>");
    }

    public void monospaced() {
        writeTag("<pre>");
    }

    public void monospaced_() {
        writeTag("</pre>");
    }

    public void lineBreak() {
        writeTag("<br>");
    }

    public void nonBreakingSpace() {
        writeTag("&nbsp;");
    }

    public void text(String text) {
        try {
            //TODO add HTML Encoding - or figure out how to get the doxia xhtmlsink to work.
            out.write(text);
        } catch (IOException ex) {
            Logger.getLogger(MySink.class.getName()).log(Level.SEVERE, "Error writing a text; unable to generate the report");
            Logger.getLogger(MySink.class.getName()).log(Level.FINE, null, ex);
        }
    }

    public void rawText(String text) {
        try {
            out.write(text);
        } catch (IOException ex) {
            Logger.getLogger(MySink.class.getName()).log(Level.SEVERE, "Error writing raw text; unable to generate the report");
            Logger.getLogger(MySink.class.getName()).log(Level.FINE, null, ex);
        }
    }

    public void flush() {
        try {
            out.flush();
        } catch (IOException ex) {
            Logger.getLogger(MySink.class.getName()).log(Level.FINEST, null, ex);
        }
    }

    public void close() {
        flush();
        try {
            out.close();
        } catch (IOException ex) {
            Logger.getLogger(MySink.class.getName()).log(Level.FINEST, null, ex);
        }
    }

    @Override
    public void head(SinkEventAttributes sea) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void title(SinkEventAttributes sea) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void author(SinkEventAttributes sea) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void date(SinkEventAttributes sea) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void body(SinkEventAttributes sea) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void section(int i, SinkEventAttributes sea) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void section_(int i) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void sectionTitle(int i, SinkEventAttributes sea) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void sectionTitle_(int i) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void list(SinkEventAttributes sea) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void listItem(SinkEventAttributes sea) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void numberedList(int i, SinkEventAttributes sea) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void numberedListItem(SinkEventAttributes sea) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void definitionList(SinkEventAttributes sea) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void definitionListItem(SinkEventAttributes sea) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void definition(SinkEventAttributes sea) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void definedTerm(SinkEventAttributes sea) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void figure(SinkEventAttributes sea) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void figureCaption(SinkEventAttributes sea) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void figureGraphics(String string, SinkEventAttributes sea) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void table(SinkEventAttributes sea) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void tableRow(SinkEventAttributes sea) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void tableCell(SinkEventAttributes sea) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void tableHeaderCell(SinkEventAttributes sea) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void tableCaption(SinkEventAttributes sea) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void paragraph(SinkEventAttributes sea) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void verbatim(SinkEventAttributes sea) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void horizontalRule(SinkEventAttributes sea) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void anchor(String string, SinkEventAttributes sea) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void link(String string, SinkEventAttributes sea) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void lineBreak(SinkEventAttributes sea) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void text(String string, SinkEventAttributes sea) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void comment(String string) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void unknown(String string, Object[] os, SinkEventAttributes sea) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void enableLogging(Log log) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
}
