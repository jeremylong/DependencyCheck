package org.owasp.dependencycheck.utils;

/**
 * Interface providing a parser for an NVD CVE URL.
 *
 * The goal of this parser is to provide methods to manipulate these URLs.
 *
 * @author nhumblot
 *
 */
public interface CveUrlParser {

  static CveUrlParser newInstance(Settings settings) {
    return new DefaultCveUrlModifiedParser(settings);
  }

  String getDefaultCveUrlModified(String baseUrl);

}
