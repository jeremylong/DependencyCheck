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
 * Copyright (c) 2018 Nicolas Henneaux. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.artifactory;

import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.data.nexus.MavenArtifact;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.utils.Settings;

import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ArtifactorySearchTest extends BaseTest {
    private ArtifactorySearch searcher;
    private static String httpsProxyHostOrig;
    private static String httpsPortOrig;

    @BeforeClass
    public static void tinkerProxies() {
        httpsProxyHostOrig = System.getProperty("https.proxyHost");
        if (httpsProxyHostOrig == null) {
            httpsProxyHostOrig = System.getenv("https.proxyHost");
        }
        httpsPortOrig = System.getProperty("https.proxyPort");
        if (httpsPortOrig == null) {
            httpsPortOrig = System.getenv("https.proxyPort");
        }
        System.setProperty("https.proxyHost", "");
        System.setProperty("https.proxyPort", "");
    }

    @AfterClass
    public static void restoreProxies() {
        if (httpsProxyHostOrig != null) {
            System.setProperty("https.proxyHost", httpsProxyHostOrig);
        }
        if (httpsPortOrig != null) {
            System.setProperty("https.proxyPort", httpsPortOrig);
        }
    }

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        searcher = new ArtifactorySearch(getSettings());
    }


    @Test
    public void shouldFailWhenHostUnknown() throws IOException {
        // Given
        Dependency dependency = new Dependency();
        dependency.setSha1sum("c5b4c491aecb72e7c32a78da0b5c6b9cda8dee0f");
        dependency.setSha256sum("512b4bf6927f4864acc419b8c5109c23361c30ed1f5798170248d33040de068e");
        dependency.setMd5sum("2d1dd0fc21ee96bccfab4353d5379649");

        final Settings settings = getSettings();
        settings.setString(Settings.KEYS.ANALYZER_ARTIFACTORY_URL, "https://artifactory.techno.ingenico.com.non-existing/artifactory");
        final ArtifactorySearch artifactorySearch = new ArtifactorySearch(settings);
        // When
        try {
            artifactorySearch.search(dependency);
            fail();
        } catch (UnknownHostException exception) {
            // Then
            assertEquals("artifactory.techno.ingenico.com.non-existing", exception.getMessage());
        } catch (SocketTimeoutException exception) {
            // Then
            assertEquals("connect timed out", exception.getMessage());
        } catch (IOException ex) {
            assertEquals("Connection refused (Connection refused)", ex.getMessage());
        }
    }


    @Test
    public void shouldProcessCorrectlyArtifactoryAnswerWithoutSha256() throws IOException {
        // Given
        Dependency dependency = new Dependency();
        dependency.setSha1sum("2e66da15851f9f5b5079228f856c2f090ba98c38");
        dependency.setMd5sum("3dbee72667f107b4f76f2d5aa33c5687");
        final HttpURLConnection urlConnection = mock(HttpURLConnection.class);
        final byte[] payload = ("{\n" +
                "  \"results\" : [ {\n" +
                "    \"repo\" : \"jcenter-cache\",\n" +
                "    \"path\" : \"/com/google/code/gson/gson/2.1/gson-2.1.jar\",\n" +
                "    \"created\" : \"2017-06-14T16:15:37.936+02:00\",\n" +
                "    \"createdBy\" : \"anonymous\",\n" +
                "    \"lastModified\" : \"2012-12-12T22:20:22.000+01:00\",\n" +
                "    \"modifiedBy\" : \"anonymous\",\n" +
                "    \"lastUpdated\" : \"2017-06-14T16:15:37.939+02:00\",\n" +
                "    \"properties\" : {\n" +
                "      \"artifactory.internal.etag\" : [ \"2e66da15851f9f5b5079228f856c2f090ba98c38\" ]\n" +
                "    },\n" +
                "    \"downloadUri\" : \"https://artifactory.techno.ingenico.com/artifactory/jcenter-cache/com/google/code/gson/gson/2.1/gson-2.1.jar\",\n" +
                "    \"remoteUrl\" : \"http://jcenter.bintray.com/com/google/code/gson/gson/2.1/gson-2.1.jar\",\n" +
                "    \"mimeType\" : \"application/java-archive\",\n" +
                "    \"size\" : \"180110\",\n" +
                "    \"checksums\" : {\n" +
                "      \"sha1\" : \"2e66da15851f9f5b5079228f856c2f090ba98c38\",\n" +
                "      \"md5\" : \"3dbee72667f107b4f76f2d5aa33c5687\"\n" +
                "    },\n" +
                "    \"originalChecksums\" : {\n" +
                "      \"sha1\" : \"2e66da15851f9f5b5079228f856c2f090ba98c38\"\n" +
                "    },\n" +
                "    \"uri\" : \"https://artifactory.techno.ingenico.com/artifactory/api/storage/jcenter-cache/com/google/code/gson/gson/2.1/gson-2.1.jar\"\n" +
                "  } ]\n" +
                "}").getBytes(StandardCharsets.UTF_8);
        when(urlConnection.getInputStream()).thenReturn(new ByteArrayInputStream(payload));

        // When
        final List<MavenArtifact> mavenArtifacts = searcher.processResponse(dependency, urlConnection);

        // Then

        assertEquals(1, mavenArtifacts.size());
        final MavenArtifact artifact = mavenArtifacts.get(0);
        assertEquals("com.google.code.gson", artifact.getGroupId());
        assertEquals("gson", artifact.getArtifactId());
        assertEquals("2.1", artifact.getVersion());
        assertEquals("https://artifactory.techno.ingenico.com/artifactory/jcenter-cache/com/google/code/gson/gson/2.1/gson-2.1.jar", artifact.getArtifactUrl());
        assertEquals("https://artifactory.techno.ingenico.com/artifactory/jcenter-cache/com/google/code/gson/gson/2.1/gson-2.1.pom", artifact.getPomUrl());
    }

    @Test
    public void shouldProcessCorrectlyArtifactoryAnswerWithMultipleMatches() throws IOException {
        // Given
        Dependency dependency = new Dependency();
        dependency.setSha1sum("94a9ce681a42d0352b3ad22659f67835e560d107");
        dependency.setMd5sum("03dcfdd88502505cc5a805a128bfdd8d");
        final HttpURLConnection urlConnection = mock(HttpURLConnection.class);
        final byte[] payload = multipleMatchesPayload();
        when(urlConnection.getInputStream()).thenReturn(new ByteArrayInputStream(payload));

        // When
        final List<MavenArtifact> mavenArtifacts = searcher.processResponse(dependency, urlConnection);

        // Then

        assertEquals(2, mavenArtifacts.size());
        final MavenArtifact artifact1 = mavenArtifacts.get(0);
        assertEquals("axis", artifact1.getGroupId());
        assertEquals("axis", artifact1.getArtifactId());
        assertEquals("1.4", artifact1.getVersion());
        assertEquals("https://artifactory.techno.ingenico.com/artifactory/gradle-libs-cache/axis/axis/1.4/axis-1.4.jar", artifact1.getArtifactUrl());
        assertEquals("https://artifactory.techno.ingenico.com/artifactory/gradle-libs-cache/axis/axis/1.4/axis-1.4.pom", artifact1.getPomUrl());
        final MavenArtifact artifact2 = mavenArtifacts.get(1);
        assertEquals("org.apache.axis", artifact2.getGroupId());
        assertEquals("axis", artifact2.getArtifactId());
        assertEquals("1.4", artifact2.getVersion());
        assertEquals("https://artifactory.techno.ingenico.com/artifactory/gradle-libs-cache/org/apache/axis/axis/1.4/axis-1.4.jar", artifact2.getArtifactUrl());
        assertEquals("https://artifactory.techno.ingenico.com/artifactory/gradle-libs-cache/org/apache/axis/axis/1.4/axis-1.4.pom", artifact2.getPomUrl());
    }

    @Test
    public void shouldHandleNoMatches() throws IOException {
        // Given
        Dependency dependency = new Dependency();
        dependency.setSha1sum("94a9ce681a42d0352b3ad22659f67835e560d108");
        final HttpURLConnection urlConnection = mock(HttpURLConnection.class);
        final byte[] payload = ("{\n" +
                "  \"results\" : [ ]}").getBytes(StandardCharsets.UTF_8);
        when(urlConnection.getInputStream()).thenReturn(new ByteArrayInputStream(payload));

        // When
        try {
            searcher.processResponse(dependency, urlConnection);
            fail("No Match found, should throw an exception!");
        } catch (FileNotFoundException e) {
            // Then
            assertEquals("Artifact Dependency{ fileName='null', actualFilePath='null', filePath='null', packagePath='null'} not found in Artifactory", e.getMessage());
        }
    }

    private byte[] multipleMatchesPayload() {
        return ("{\n" +
                "  \"results\" : [ {\n" +
                "    \"repo\" : \"gradle-libs-cache\",\n" +
                "    \"path\" : \"/axis/axis/1.4/axis-1.4.jar\",\n" +
                "    \"created\" : \"2015-07-17T08:58:28.039+02:00\",\n" +
                "    \"createdBy\" : \"loic\",\n" +
                "    \"lastModified\" : \"2006-04-23T06:32:12.000+02:00\",\n" +
                "    \"modifiedBy\" : \"loic\",\n" +
                "    \"lastUpdated\" : \"2015-07-17T08:58:28.049+02:00\",\n" +
                "    \"properties\" : {\n" +
                "    },\n" +
                "    \"downloadUri\" : \"https://artifactory.techno.ingenico.com/artifactory/gradle-libs-cache/axis/axis/1.4/axis-1.4.jar\",\n" +
                "    \"remoteUrl\" : \"http://gradle.artifactoryonline.com/gradle/libs/axis/axis/1.4/axis-1.4.jar\",\n" +
                "    \"mimeType\" : \"application/java-archive\",\n" +
                "    \"size\" : \"1599570\",\n" +
                "    \"checksums\" : {\n" +
                "      \"sha1\" : \"94a9ce681a42d0352b3ad22659f67835e560d107\",\n" +
                "      \"md5\" : \"03dcfdd88502505cc5a805a128bfdd8d\"\n" +
                "    },\n" +
                "    \"originalChecksums\" : {\n" +
                "      \"sha1\" : \"94a9ce681a42d0352b3ad22659f67835e560d107\",\n" +
                "      \"md5\" : \"03dcfdd88502505cc5a805a128bfdd8d\"\n" +
                "    },\n" +
                "    \"uri\" : \"https://artifactory.techno.ingenico.com/artifactory/api/storage/gradle-libs-cache/axis/axis/1.4/axis-1.4.jar\"\n" +
                "  }, {\n" +
                "    \"repo\" : \"gradle-libs-cache\",\n" +
                "    \"path\" : \"/org/apache/axis/axis/1.4/axis-1.4.jar\",\n" +
                "    \"created\" : \"2015-07-09T10:09:43.074+02:00\",\n" +
                "    \"createdBy\" : \"fabrizio\",\n" +
                "    \"lastModified\" : \"2006-04-23T07:16:56.000+02:00\",\n" +
                "    \"modifiedBy\" : \"fabrizio\",\n" +
                "    \"lastUpdated\" : \"2015-07-09T10:09:43.082+02:00\",\n" +
                "    \"properties\" : {\n" +
                "    },\n" +
                "    \"downloadUri\" : \"https://artifactory.techno.ingenico.com/artifactory/gradle-libs-cache/org/apache/axis/axis/1.4/axis-1.4.jar\",\n" +
                "    \"remoteUrl\" : \"http://gradle.artifactoryonline.com/gradle/libs/org/apache/axis/axis/1.4/axis-1.4.jar\",\n" +
                "    \"mimeType\" : \"application/java-archive\",\n" +
                "    \"size\" : \"1599570\",\n" +
                "    \"checksums\" : {\n" +
                "      \"sha1\" : \"94a9ce681a42d0352b3ad22659f67835e560d107\",\n" +
                "      \"md5\" : \"03dcfdd88502505cc5a805a128bfdd8d\"\n" +
                "    },\n" +
                "    \"originalChecksums\" : {\n" +
                "      \"sha1\" : \"94a9ce681a42d0352b3ad22659f67835e560d107\",\n" +
                "      \"md5\" : \"03dcfdd88502505cc5a805a128bfdd8d\"\n" +
                "    },\n" +
                "    \"uri\" : \"https://artifactory.techno.ingenico.com/artifactory/api/storage/gradle-libs-cache/org/apache/axis/axis/1.4/axis-1.4.jar\"\n" +
                "  } ]}").getBytes(StandardCharsets.UTF_8);
    }

    @Test
    public void shouldProcessCorrectlyArtifactoryAnswer() throws IOException {
        // Given
        Dependency dependency = new Dependency();
        dependency.setSha1sum("c5b4c491aecb72e7c32a78da0b5c6b9cda8dee0f");
        dependency.setSha256sum("512b4bf6927f4864acc419b8c5109c23361c30ed1f5798170248d33040de068e");
        dependency.setMd5sum("2d1dd0fc21ee96bccfab4353d5379649");
        final HttpURLConnection urlConnection = mock(HttpURLConnection.class);
        final byte[] payload = payloadWithSha256().getBytes(StandardCharsets.UTF_8);
        when(urlConnection.getInputStream()).thenReturn(new ByteArrayInputStream(payload));

        // When
        final List<MavenArtifact> mavenArtifacts = searcher.processResponse(dependency, urlConnection);

        // Then

        assertEquals(1, mavenArtifacts.size());
        final MavenArtifact artifact = mavenArtifacts.get(0);
        assertEquals("com.google.code.gson", artifact.getGroupId());
        assertEquals("gson", artifact.getArtifactId());
        assertEquals("2.8.5", artifact.getVersion());
        assertEquals("https://artifactory.techno.ingenico.com/artifactory/repo1-cache/com/google/code/gson/gson/2.8.5/gson-2.8.5-sources.jar", artifact.getArtifactUrl());
        assertEquals("https://artifactory.techno.ingenico.com/artifactory/repo1-cache/com/google/code/gson/gson/2.8.5/gson-2.8.5.pom", artifact.getPomUrl());
    }

    private String payloadWithSha256() {
        return "{\n" +
                "  \"results\" : [ {\n" +
                "    \"repo\" : \"repo1-cache\",\n" +
                "    \"path\" : \"/com/google/code/gson/gson/2.8.5/gson-2.8.5-sources.jar\",\n" +
                "    \"created\" : \"2018-06-20T12:05:23.295+02:00\",\n" +
                "    \"createdBy\" : \"nhenneaux\",\n" +
                "    \"lastModified\" : \"2018-05-22T05:09:01.000+02:00\",\n" +
                "    \"modifiedBy\" : \"nhenneaux\",\n" +
                "    \"lastUpdated\" : \"2018-06-20T12:05:23.302+02:00\",\n" +
                "    \"properties\" : {\n" +
                "      \"artifactory.internal.etag\" : [ \"\\\"2d1dd0fc21ee96bccfab4353d5379649\\\"\" ]\n" +
                "    },\n" +
                "    \"downloadUri\" : \"https://artifactory.techno.ingenico.com/artifactory/repo1-cache/com/google/code/gson/gson/2.8.5/gson-2.8.5-sources.jar\",\n" +
                "    \"remoteUrl\" : \"http://repo1.maven.org/maven2/com/google/code/gson/gson/2.8.5/gson-2.8.5-sources.jar\",\n" +
                "    \"mimeType\" : \"application/java-archive\",\n" +
                "    \"size\" : \"156280\",\n" +
                "    \"checksums\" : {\n" +
                "      \"sha1\" : \"c5b4c491aecb72e7c32a78da0b5c6b9cda8dee0f\",\n" +
                "      \"md5\" : \"2d1dd0fc21ee96bccfab4353d5379649\",\n" +
                "      \"sha256\" : \"512b4bf6927f4864acc419b8c5109c23361c30ed1f5798170248d33040de068e\"\n" +
                "    },\n" +
                "    \"originalChecksums\" : {\n" +
                "      \"sha1\" : \"c5b4c491aecb72e7c32a78da0b5c6b9cda8dee0f\",\n" +
                "      \"md5\" : \"2d1dd0fc21ee96bccfab4353d5379649\",\n" +
                "      \"sha256\" : \"512b4bf6927f4864acc419b8c5109c23361c30ed1f5798170248d33040de068e\"\n" +
                "    },\n" +
                "    \"uri\" : \"https://artifactory.techno.ingenico.com/artifactory/api/storage/repo1-cache/com/google/code/gson/gson/2.8.5/gson-2.8.5-sources.jar\"\n" +
                "  } ]\n" +
                "}";
    }

    @Test
    public void shouldProcessCorrectlyArtifactoryAnswerMisMatchMd5() throws IOException {
        // Given
        Dependency dependency = new Dependency();
        dependency.setSha1sum("c5b4c491aecb72e7c32a78da0b5c6b9cda8dee0f");
        dependency.setSha256sum("512b4bf6927f4864acc419b8c5109c23361c30ed1f5798170248d33040de068e");
        dependency.setMd5sum("2d1dd0fc21ee96bccfab4353d5379640");
        final HttpURLConnection urlConnection = mock(HttpURLConnection.class);
        final byte[] payload = payloadWithSha256().getBytes(StandardCharsets.UTF_8);
        when(urlConnection.getInputStream()).thenReturn(new ByteArrayInputStream(payload));

        // When
        try {
            searcher.processResponse(dependency, urlConnection);
            fail("MD5 mismatching should throw an exception!");
        } catch (FileNotFoundException e) {
            // Then
            assertEquals("Artifact found by API is not matching the md5 of the artifact (repository hash is 2d1dd0fc21ee96bccfab4353d5379649 while actual is 2d1dd0fc21ee96bccfab4353d5379640) !", e.getMessage());
        }
    }

    @Test
    public void shouldProcessCorrectlyArtifactoryAnswerMisMatchSha1() throws IOException {
        // Given
        Dependency dependency = new Dependency();
        dependency.setSha1sum("c5b4c491aecb72e7c32a78da0b5c6b9cda8dee0e");
        dependency.setSha256sum("512b4bf6927f4864acc419b8c5109c23361c30ed1f5798170248d33040de068e");
        dependency.setMd5sum("2d1dd0fc21ee96bccfab4353d5379649");
        final HttpURLConnection urlConnection = mock(HttpURLConnection.class);
        final byte[] payload = payloadWithSha256().getBytes(StandardCharsets.UTF_8);
        when(urlConnection.getInputStream()).thenReturn(new ByteArrayInputStream(payload));

        // When
        try {
            searcher.processResponse(dependency, urlConnection);
            fail("SHA1 mismatching should throw an exception!");
        } catch (FileNotFoundException e) {
            // Then
            assertEquals("Artifact found by API is not matching the SHA1 of the artifact (repository hash is c5b4c491aecb72e7c32a78da0b5c6b9cda8dee0f while actual is c5b4c491aecb72e7c32a78da0b5c6b9cda8dee0e) !", e.getMessage());
        }
    }

    @Test
    public void shouldProcessCorrectlyArtifactoryAnswerMisMatchSha256() throws IOException {
        // Given
        Dependency dependency = new Dependency();
        dependency.setSha1sum("c5b4c491aecb72e7c32a78da0b5c6b9cda8dee0f");
        dependency.setSha256sum("512b4bf6927f4864acc419b8c5109c23361c30ed1f5798170248d33040de068f");
        dependency.setMd5sum("2d1dd0fc21ee96bccfab4353d5379649");
        final HttpURLConnection urlConnection = mock(HttpURLConnection.class);
        final byte[] payload = payloadWithSha256().getBytes(StandardCharsets.UTF_8);
        when(urlConnection.getInputStream()).thenReturn(new ByteArrayInputStream(payload));

        // When
        try {
            searcher.processResponse(dependency, urlConnection);
            fail("SHA256 mismatching should throw an exception!");
        } catch (FileNotFoundException e) {
            // Then
            assertEquals("Artifact found by API is not matching the SHA-256 of the artifact (repository hash is 512b4bf6927f4864acc419b8c5109c23361c30ed1f5798170248d33040de068e while actual is 512b4bf6927f4864acc419b8c5109c23361c30ed1f5798170248d33040de068f) !", e.getMessage());
        }
    }

    @Test
    public void shouldThrowExceptionWhenPatternCannotBeParsed() throws IOException {
        // Given
        Dependency dependency = new Dependency();
        dependency.setSha1sum("c5b4c491aecb72e7c32a78da0b5c6b9cda8dee0f");
        dependency.setSha256sum("512b4bf6927f4864acc419b8c5109c23361c30ed1f5798170248d33040de068e");
        dependency.setMd5sum("2d1dd0fc21ee96bccfab4353d5379649");
        final HttpURLConnection urlConnection = mock(HttpURLConnection.class);
        final byte[] payload = payloadWithSha256().replace("/com/google/code/gson/gson/2.8.5/gson-2.8.5-sources.jar", "/2.8.5/gson-2.8.5-sources.jar").getBytes(StandardCharsets.UTF_8);
        when(urlConnection.getInputStream()).thenReturn(new ByteArrayInputStream(payload));

        // When
        try {
            searcher.processResponse(dependency, urlConnection);
            fail("SHA256 mismatching should throw an exception!");
        } catch (IllegalStateException e) {
            // Then
            assertEquals("Cannot extract the Maven information from the path retrieved in Artifactory /2.8.5/gson-2.8.5-sources.jar", e.getMessage());
        }
    }
}
