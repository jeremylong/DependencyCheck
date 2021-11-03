package org.owasp.dependencycheck.resources;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.junit.Assert;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public class DependencyCheckBaseSuppressionTest {

    @Test
    public void testAllSuppressionsHaveBaseAttribute() throws ParserConfigurationException, SAXException, IOException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);

        Path path = Paths.get("src", "main", "resources", "dependencycheck-base-suppression.xml");
        File file = path.toFile();
        boolean e = file.exists();
        Document document = factory.newDocumentBuilder().parse(file);
        document.getDocumentElement().normalize();

        NodeList nodes = document.getElementsByTagName("suppress");

        int numberOfSuppressTagsWithoutBaseTrueAttribute = 0;
        for (int i = 0; i < nodes.getLength(); i++) {
            Node node = nodes.item(i);

            if (node.getNodeType() == Node.ELEMENT_NODE) {
                Element element = (Element) node;

                if (!"true".equalsIgnoreCase(element.getAttribute("base"))) {
                    numberOfSuppressTagsWithoutBaseTrueAttribute++;
                }
            }
        }

        Assert.assertEquals(0, numberOfSuppressTagsWithoutBaseTrueAttribute);
    }
}
