package org.owasp.dependencycheck.utils;

import java.util.Objects;

/**
 * Default implementation of a {@code CveUrlParser}.
 *
 * @author nhumblot
 *
 */
public final class DefaultCveUrlModifiedParser implements CveUrlParser {

  private static final String URL_SEPARATOR = "/";

  private final Settings settings;

  DefaultCveUrlModifiedParser(Settings settings) {
    this.settings = settings;
  }

  @Override
  public String getDefaultCveUrlModified(String baseUrl) {
    String defaultBaseUrlEnd = URL_SEPARATOR + settings.getString(Settings.KEYS.CVE_BASE_DEFAULT_FILENAME);
    if (Objects.nonNull(baseUrl) && baseUrl.endsWith(defaultBaseUrlEnd)) {
      String defaultModifiedUrlEnd = URL_SEPARATOR + settings.getString(Settings.KEYS.CVE_MODIFIED_DEFAULT_FILENAME);
      return baseUrl.substring(0, baseUrl.length() - defaultBaseUrlEnd.length()) + defaultModifiedUrlEnd;
    }
    return null;
  }
}
