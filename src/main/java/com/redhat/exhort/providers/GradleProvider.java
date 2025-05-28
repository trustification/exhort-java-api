/*
 * Copyright © 2023 Red Hat, Inc.
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
 */
package com.redhat.exhort.providers;

import static com.redhat.exhort.impl.ExhortApi.debugLoggingIsNeeded;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import com.redhat.exhort.Api;
import com.redhat.exhort.Provider;
import com.redhat.exhort.logging.LoggersFactory;
import com.redhat.exhort.sbom.Sbom;
import com.redhat.exhort.sbom.SbomFactory;
import com.redhat.exhort.tools.Ecosystem.Type;
import com.redhat.exhort.tools.Operations;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.tomlj.Toml;
import org.tomlj.TomlParseResult;
import org.tomlj.TomlTable;

/**
 * Concrete implementation of the {@link Provider} used for converting dependency trees for Gradle
 * projects (gradle.build / gradle.build.kts) into a content Dot Graphs for Stack analysis or Json
 * for Component analysis.
 */
public final class GradleProvider extends BaseJavaProvider {

  public static final String[] COMPONENT_ANALYSIS_CONFIGURATIONS = {
    "api", "implementation", "compileOnlyApi", "compileOnly", "runtimeOnly"
  };
  private static final Logger log = LoggersFactory.getLogger(GradleProvider.class.getName());

  private final String gradleExecutable = Operations.getExecutable("gradle", "--version");

  public GradleProvider(Path manifest) {
    super(Type.GRADLE, manifest);
  }

  @Override
  public Content provideStack() throws IOException {
    Path tempFile = getDependencies(manifest);
    if (debugLoggingIsNeeded()) {
      String stackAnalysisDependencyTree = Files.readString(tempFile);
      log.info(
          String.format(
              "Package Manager Gradle Stack Analysis Dependency Tree Output: %s %s",
              System.lineSeparator(), stackAnalysisDependencyTree));
    }
    Map<String, String> propertiesMap = extractProperties(manifest);

    var sbom = buildSbomFromTextFormat(tempFile, propertiesMap, new String[] {"runtimeClasspath"});
    var ignored = getIgnoredDeps(manifest);

    return new Content(
        sbom.filterIgnoredDeps(ignored).getAsJsonString().getBytes(), Api.CYCLONEDX_MEDIA_TYPE);
  }

  private List<String> getIgnoredDeps(Path manifestPath) throws IOException {
    List<String> buildGradleLines = Files.readAllLines(manifestPath);
    List<String> ignored = new ArrayList<>();

    var ignoredLines =
        buildGradleLines.stream()
            .filter(this::isIgnoredLine)
            .map(this::extractPackageName)
            .collect(Collectors.toList());

    // Process each ignored dependency
    for (String dependency : ignoredLines) {
      String ignoredDepInfo;
      if (depHasLibsNotation(dependency)) {
        ignoredDepInfo = getDepFromNotation(dependency, manifestPath);
      } else {
        ignoredDepInfo = getDepInfo(dependency);
      }

      if (ignoredDepInfo != null) {
        ignored.add(ignoredDepInfo);
      }
    }

    return ignored;
  }

  private String getDepInfo(String dependencyLine) {
    // Check if the line contains "group:", "name:", and "version:"
    if (dependencyLine.contains("group:")
        && dependencyLine.contains("name:")
        && dependencyLine.contains("version:")) {
      Pattern pattern = Pattern.compile("(group|name|version):\\s*['\"](.*?)['\"]");
      Matcher matcher = pattern.matcher(dependencyLine);
      String groupId = null, artifactId = null, version = null;

      while (matcher.find()) {
        String key = matcher.group(1);
        String value = matcher.group(2);

        switch (key) {
          case "group":
            groupId = value;
            break;
          case "name":
            artifactId = value;
            break;
          case "version":
            version = value;
            break;
        }
      }
      if (groupId != null && artifactId != null && version != null) {
        PackageURL ignoredPackageUrl = toPurl(groupId, artifactId, version);
        return ignoredPackageUrl.getCoordinates();
      }
    } else {
      // Regular expression pattern to capture content inside single or double quotes
      Pattern pattern = Pattern.compile("['\"](.*?)['\"]");
      Matcher matcher = pattern.matcher(dependencyLine);
      // Check if the matcher finds a match
      if (matcher.find()) {
        // Get the matched string inside single or double quotes
        String dependency = matcher.group(1);
        String[] dependencyParts = dependency.split(":");
        if (dependencyParts.length == 3) {
          // Extract groupId, artifactId, and version
          String groupId = dependencyParts[0];
          String artifactId = dependencyParts[1];
          String version = dependencyParts[2];

          PackageURL ignoredPackageUrl = toPurl(groupId, artifactId, version);
          return ignoredPackageUrl.getCoordinates();
        }
      }
    }
    return null;
  }

  private String getDepFromNotation(String dependency, Path manifestPath) throws IOException {
    // Extract everything after "libs."
    String alias = dependency.substring(dependency.indexOf("libs.") + "libs.".length()).trim();
    alias = alias.replace(".", "-").replace(")", "");

    // Read and parse the TOML file
    TomlParseResult toml = Toml.parse(getLibsVersionsTomlPath(manifestPath));
    TomlTable librariesTable = toml.getTable("libraries");
    TomlTable dependencyTable = librariesTable.getTable(alias);
    if (dependencyTable != null) {
      String groupId = dependencyTable.getString("module").split(":")[0];
      String artifactId = dependencyTable.getString("module").split(":")[1];
      String version =
          toml.getTable("versions").getString(dependencyTable.getString("version.ref"));
      PackageURL ignoredPackageUrl = toPurl(groupId, artifactId, version);
      return ignoredPackageUrl.getCoordinates();
    }

    return null;
  }

  private Path getLibsVersionsTomlPath(Path manifestPath) {
    return manifestPath.getParent().resolve("gradle/libs.versions.toml");
  }

  public PackageURL toPurl(String groupId, String artifactId, String version) {
    try {
      return new PackageURL(Type.MAVEN.getType(), groupId, artifactId, version, null, null);
    } catch (MalformedPackageURLException e) {
      throw new IllegalArgumentException("Unable to parse PackageURL", e);
    }
  }

  private boolean depHasLibsNotation(String depToBeIgnored) {
    Pattern pattern = Pattern.compile(":");
    Matcher matcher = pattern.matcher(depToBeIgnored.trim());
    return (depToBeIgnored.trim().startsWith("library(") || depToBeIgnored.trim().contains("libs."))
        && (matcher.results().count() <= 1);
  }

  private boolean isIgnoredLine(String line) {
    return line.contains("exhortignore");
  }

  private String extractPackageName(String line) {
    String packageName = line.trim();
    // Extract the package name before the comment
    int commentIndex = packageName.indexOf("//");
    if (commentIndex != -1) {
      packageName = packageName.substring(0, commentIndex).trim();
    }
    // Remove any other trailing comments or spaces
    commentIndex = packageName.indexOf("/*");
    if (commentIndex != -1) {
      packageName = packageName.substring(0, commentIndex).trim();
    }
    return packageName;
  }

  private Path getDependencies(Path manifestPath) throws IOException {
    // create a temp file for storing the dependency tree in
    var tempFile = Files.createTempFile("exhort_graph_", null);
    // the command will create the dependency tree in the temp file
    String gradleCommand = gradleExecutable + " dependencies";

    String[] cmdList = gradleCommand.split("\\s+");
    String gradleOutput =
        Operations.runProcessGetOutput(Path.of(manifestPath.getParent().toString()), cmdList);
    Files.writeString(tempFile, gradleOutput);

    return tempFile;
  }

  protected Path getProperties(Path manifestPath) throws IOException {
    Path propsTempFile = Files.createTempFile("propsfile", ".txt");
    String propCmd = gradleExecutable + " properties";
    String[] propCmdList = propCmd.split("\\s+");
    String properties =
        Operations.runProcessGetOutput(Path.of(manifestPath.getParent().toString()), propCmdList);
    // Create a temporary file
    Files.writeString(propsTempFile, properties);

    return propsTempFile;
  }

  private Sbom buildSbomFromTextFormat(
      Path textFormatFile, Map<String, String> propertiesMap, String[] configNames)
      throws IOException {
    var sbom = SbomFactory.newInstance(Sbom.BelongingCondition.PURL, "sensitive");
    String root = getRoot(textFormatFile, propertiesMap);

    var rootPurl = parseDep(root);
    sbom.addRoot(rootPurl);
    List<String> lines = new ArrayList<>();

    for (String configName : configNames) {
      List<String> deps = extractLines(textFormatFile, configName);
      lines.addAll(deps);
    }

    List<String> arrayForSbom = new ArrayList<>();

    for (String line : lines) {
      line = line.replaceAll("---", "-").replaceAll("    ", "  ");
      line = line.replaceAll(":(.*):(.*) -> (.*)$", ":$1:$3");
      line = line.replaceAll("(.*):(.*):(.*)$", "$1:$2:jar:$3");
      line = line.replaceAll(" \\(n\\)$", "");
      line = line.replaceAll(" \\(\\*\\)", "");
      line = line.replaceAll("$", ":compile");
      if (containsVersion(line)) {
        arrayForSbom.add(line);
      }
    }
    // remove duplicates for component analysis
    if (Arrays.equals(configNames, COMPONENT_ANALYSIS_CONFIGURATIONS)) {
      removeDuplicateIfExists(arrayForSbom, textFormatFile);
      arrayForSbom = performManifestVersionsCheck(arrayForSbom, textFormatFile);
    }

    String[] array = arrayForSbom.toArray(new String[0]);
    parseDependencyTree(root, 0, array, sbom);
    return sbom;
  }

  private List<String> performManifestVersionsCheck(List<String> arrayForSbom, Path textFormatFile)
      throws IOException {

    List<String> runtimeClasspathLines = extractLines(textFormatFile, "runtimeClasspath");
    Map<String, String> runtimeClasspathVersions = parseDependencyVersions(runtimeClasspathLines);
    List<String> updatedLines = updateDependencies(arrayForSbom, runtimeClasspathVersions);

    return updatedLines;
  }

  private Map<String, String> parseDependencyVersions(List<String> lines) {
    Map<String, String> dependencyVersions = new HashMap<>();

    for (String line : lines) {
      if (line.contains("->")) {
        String[] splitLine = line.split("---");
        if (splitLine.length > 1) {
          String dependencyPart = splitLine[1].trim();
          String[] parts = dependencyPart.split("-> ");
          // Extract the dependency name (without the version) and the resolved version
          String dependency = parts[0].substring(0, parts[0].lastIndexOf(':')).trim();
          String version = parts[1].split(" ")[0].trim();
          dependencyVersions.put(dependency, version);
        }
      }
    }

    return dependencyVersions;
  }

  private List<String> updateDependencies(
      List<String> lines, Map<String, String> runtimeClasspathVersions) {
    List<String> updatedLines = new ArrayList<>();
    for (String line : lines) {
      PackageURL packageURL = parseDep(line);
      String[] parts = line.split(":");
      if (parts.length >= 4) {
        String dependencyKey =
            packageURL.getNamespace() + ":" + packageURL.getName(); // Extract dependency key
        if (runtimeClasspathVersions.containsKey(dependencyKey)) {
          String newVersion = runtimeClasspathVersions.get(dependencyKey);
          parts[3] = newVersion; // Replace version with the resolved version
          updatedLines.add(String.join(":", parts));
        } else {
          updatedLines.add(line); // Keep the original line if no update is needed
        }
      } else {
        updatedLines.add(line); // Keep the original line if it doesn't match the expected pattern
      }
    }
    return updatedLines;
  }

  private void removeDuplicateIfExists(List<String> arrayForSbom, Path theContent) {
    Consumer<String> removeDuplicateFunction =
        dependency -> {
          try {
            String content = Files.readString(theContent);
            PackageURL depUrl = parseDep(dependency);
            String depVersion = depUrl.getVersion().trim();
            int indexOfDuplicate = -1;
            int selfIndex = -1;

            for (int i = 0; i < arrayForSbom.size(); i++) {
              PackageURL dep = parseDep(arrayForSbom.get(i));
              if (dep.getNamespace().equals(depUrl.getNamespace())
                  && dep.getName().equals(depUrl.getName())) {
                if (dep.getVersion().equals(depVersion)) {
                  selfIndex = i;
                } else if (!dep.getVersion().equals(depVersion) && indexOfDuplicate == -1) {
                  indexOfDuplicate = i;
                }
              }
            }

            if (selfIndex != -1 && selfIndex != indexOfDuplicate && indexOfDuplicate != -1) {
              PackageURL duplicateDepVersion = parseDep(arrayForSbom.get(indexOfDuplicate));
              Pattern pattern =
                  Pattern.compile(
                      ".*" + depVersion + "\\W?->\\W?" + duplicateDepVersion.getVersion() + ".*");
              Matcher matcher = pattern.matcher(content);
              if (matcher.find()) {
                arrayForSbom.remove(selfIndex);
              } else {
                pattern =
                    Pattern.compile(
                        ".*" + duplicateDepVersion.getVersion() + "\\W?->\\W?" + depVersion + ".*");
                matcher = pattern.matcher(content);
                if (matcher.find()) {
                  arrayForSbom.remove(indexOfDuplicate);
                }
              }
            }
          } catch (Exception e) {
            e.printStackTrace();
          }
        };
    List<String> copyOfArrayForSbom = new ArrayList<>(arrayForSbom);
    copyOfArrayForSbom.forEach(removeDuplicateFunction);
  }

  private boolean containsVersion(String line) {
    String lineStripped = line.replace("(n)", "").trim();
    Pattern pattern1 =
        Pattern.compile("\\W*[a-z0-9.-]+:[a-z0-9.-]+:[0-9]+[.][0-9]+(.[0-9]+)?(.*)?.*");
    Pattern pattern2 = Pattern.compile(".*version:\\s?(')?[0-9]+[.][0-9]+(.[0-9]+)?(')?");
    Matcher matcher1 = pattern1.matcher(lineStripped);
    Matcher matcher2 = pattern2.matcher(lineStripped);
    return (matcher1.find() || matcher2.find()) && !lineStripped.contains("libs.");
  }

  private String getRoot(Path textFormatFile, Map<String, String> propertiesMap)
      throws IOException {
    String group = propertiesMap.get("group");
    String version = propertiesMap.get("version");
    String rootName = extractRootProjectValue(textFormatFile);
    String root = group + ':' + rootName + ':' + "jar" + ':' + version;
    return root;
  }

  private String extractRootProjectValue(Path inputFilePath) throws IOException {
    List<String> lines = Files.readAllLines(inputFilePath);
    for (String line : lines) {
      if (line.contains("Root project")) {
        Pattern pattern = Pattern.compile("Root project '(.+)'");
        Matcher matcher = pattern.matcher(line);
        if (matcher.find()) {
          return matcher.group(1);
        }
      }
    }
    return null;
  }

  private Map<String, String> extractProperties(Path manifestPath) throws IOException {
    Path propsTempFile = getProperties(manifestPath);
    String content = Files.readString(propsTempFile);
    // Define the regular expression pattern for key-value pairs
    Pattern pattern = Pattern.compile("([^:]+):\\s+(.+)");
    Matcher matcher = pattern.matcher(content);
    // Create a Map to store key-value pairs
    Map<String, String> keyValueMap = new HashMap<>();

    // Iterate through matches and add them to the map
    while (matcher.find()) {
      String key = matcher.group(1).trim();
      String value = matcher.group(2).trim();
      keyValueMap.put(key, value);
    }
    // Check if any key-value pairs were found
    if (!keyValueMap.isEmpty()) {
      return keyValueMap;
    } else {
      return Collections.emptyMap();
    }
  }

  private List<String> extractLines(Path inputFilePath, String startMarker) throws IOException {
    List<String> lines = Files.readAllLines(inputFilePath);
    List<String> extractedLines = new ArrayList<>();
    boolean startFound = false;

    for (String line : lines) {
      // If the start marker is found, set startFound to true
      if (line.startsWith(startMarker)) {
        startFound = true;
        continue; // Skip the line containing the startMarker
      }
      // If startFound is true and the line is not empty, add it to the extractedLines list
      if (startFound && !line.trim().isEmpty()) {
        extractedLines.add(line);
      }
      // If an empty line is encountered, break out of the loop
      if (startFound && line.trim().isEmpty()) {
        break;
      }
    }
    return extractedLines;
  }

  @Override
  public Content provideComponent() throws IOException {

    Path tempFile = getDependencies(manifest);
    Map<String, String> propertiesMap = extractProperties(manifest);

    String[] configurationNames = COMPONENT_ANALYSIS_CONFIGURATIONS;

    var sbom = buildSbomFromTextFormat(tempFile, propertiesMap, configurationNames);
    var ignored = getIgnoredDeps(manifest);

    return new Content(
        sbom.filterIgnoredDeps(ignored).getAsJsonString().getBytes(), Api.CYCLONEDX_MEDIA_TYPE);
  }
}
