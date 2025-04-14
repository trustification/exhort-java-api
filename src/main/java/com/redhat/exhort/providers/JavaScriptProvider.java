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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import com.redhat.exhort.Api;
import com.redhat.exhort.Provider;
import com.redhat.exhort.sbom.Sbom;
import com.redhat.exhort.sbom.SbomFactory;
import com.redhat.exhort.tools.Ecosystem;
import com.redhat.exhort.tools.Operations;
import com.redhat.exhort.utils.Environment;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

/**
 * Abstract implementation of the {@link Provider} used for converting dependency trees for
 * Javascript/Typescript projects (package.json) into a SBOM content for Stack analysis or Component
 * analysis. See concrete implementations for more details.
 */
public abstract class JavaScriptProvider extends Provider {

  private static final String PROP_PATH = "PATH";

  private System.Logger log = System.getLogger(this.getClass().getName());

  protected final String cmd;

  public JavaScriptProvider(Path manifest, Ecosystem.Type ecosystem, String cmd) {
    super(ecosystem, manifest);
    this.cmd = Operations.getCustomPathOrElse(cmd);
  }

  protected final String packageManager() {
    return cmd;
  }

  protected abstract String lockFileName();

  protected abstract String pathEnv();

  protected abstract String[] updateLockFileCmd(Path manifestDir);

  protected abstract String[] listDepsCmd(boolean includeTransitive, Path manifestDir);

  @Override
  public Content provideStack() throws IOException {
    // check for custom npm executable
    Sbom sbom = getDependencySbom(manifest, true);
    return new Content(
        sbom.getAsJsonString().getBytes(StandardCharsets.UTF_8), Api.CYCLONEDX_MEDIA_TYPE);
  }

  @Override
  public Content provideComponent() throws IOException {
    return new Content(
        getDependencySbom(manifest, false).getAsJsonString().getBytes(StandardCharsets.UTF_8),
        Api.CYCLONEDX_MEDIA_TYPE);
  }

  private PackageURL getRoot(JsonNode jsonDependenciesNpm) throws MalformedPackageURLException {
    return toPurl(
        jsonDependenciesNpm.get("name").asText(), jsonDependenciesNpm.get("version").asText());
  }

  private PackageURL toPurl(String name, String version) throws MalformedPackageURLException {
    String[] parts = name.split("/");
    if (parts.length == 2) {
      return new PackageURL(Ecosystem.Type.NPM.getType(), parts[0], parts[1], version, null, null);
    }
    return new PackageURL(Ecosystem.Type.NPM.getType(), null, parts[0], version, null, null);
  }

  private void addDependenciesOf(Sbom sbom, PackageURL from, JsonNode dependencies)
      throws MalformedPackageURLException {
    Iterator<Entry<String, JsonNode>> fields = dependencies.fields();
    while (fields.hasNext()) {
      Entry<String, JsonNode> e = fields.next();
      String name = e.getKey();
      JsonNode versionNode = e.getValue().get("version");
      if (versionNode == null) {
        continue; // ignore optional dependencies
      }
      String version = versionNode.asText();
      PackageURL purl = toPurl(name, version);
      sbom.addDependency(from, purl);
      JsonNode transitiveDeps = e.getValue().findValue("dependencies");
      if (transitiveDeps != null) {
        addDependenciesOf(sbom, purl, transitiveDeps);
      }
    }
  }

  private Sbom getDependencySbom(Path manifestPath, boolean includeTransitive) throws IOException {
    var depTree = buildDependencyTree(manifestPath, includeTransitive);
    var sbom = buildSbom(depTree);
    sbom.filterIgnoredDeps(getIgnoredDeps(manifestPath));
    return sbom;
  }

  protected JsonNode buildDependencyTree(Path manifestPath, boolean includeTransitive)
      throws JsonMappingException, JsonProcessingException {
    var mgrEnvs = getExecEnv();
    // clean command used to clean build target
    Path manifestDir = null;
    try {
      // MacOS requires resolving to the CanonicalPath to avoid problems with /var being a symlink
      // of /private/var
      manifestDir = Path.of(manifestPath.getParent().toFile().getCanonicalPath());
    } catch (IOException e) {
      throw new RuntimeException(
          String.format(
              "Unable to resolve manifest directory %s, got %s",
              manifestPath.getParent(), e.getMessage()));
    }
    var createPackageLock = updateLockFileCmd(manifestDir);
    // execute the clean command
    Operations.runProcess(createPackageLock, mgrEnvs);
    String[] allDeps;
    Path workDir = null;
    if (!manifestPath.getParent().toString().trim().contains(" ")) {
      allDeps = listDepsCmd(includeTransitive, manifestDir);
    } else {
      allDeps = listDepsCmd(includeTransitive, null);
      workDir = manifestPath.getParent();
    }
    // execute the clean command
    String[] envs = null;
    if (mgrEnvs != null) {
      envs =
          mgrEnvs.entrySet().stream()
              .map(e -> e.getKey() + "=" + e.getValue())
              .toArray(String[]::new);
    }
    String output = Operations.runProcessGetOutput(workDir, allDeps, envs);
    if (debugLoggingIsNeeded()) {
      log.log(
          System.Logger.Level.INFO,
          String.format("Listed Install Packages in Json : %s %s", System.lineSeparator(), output));
    }
    return objectMapper.readTree(output);
  }

  private Sbom buildSbom(JsonNode npmListResult) {
    Sbom sbom = SbomFactory.newInstance();
    try {
      PackageURL root = getRoot(npmListResult);
      sbom.addRoot(root);
      JsonNode dependencies = npmListResult.get("dependencies");
      addDependenciesOf(sbom, root, dependencies);
    } catch (MalformedPackageURLException e) {
      throw new IllegalArgumentException("Unable to parse NPM Json", e);
    }
    return sbom;
  }

  private List<String> getIgnoredDeps(Path manifestPath) throws IOException {
    var ignored = new ArrayList<String>();
    var root = new ObjectMapper().readTree(Files.newInputStream(manifestPath));
    var ignoredNode = root.withArray("exhortignore");
    if (ignoredNode == null) {
      return ignored;
    }
    for (JsonNode n : ignoredNode) {
      ignored.add(n.asText());
    }
    return ignored;
  }

  protected Map<String, String> getExecEnv() {
    String pathEnv = Environment.get(pathEnv());
    if (pathEnv != null && !pathEnv.isBlank()) {
      String path = Environment.get(PROP_PATH);
      if (path != null) {
        return Collections.singletonMap(PROP_PATH, path + File.pathSeparator + pathEnv);
      } else {
        return Collections.singletonMap(PROP_PATH, pathEnv);
      }
    }
    return null;
  }

  @Override
  public void validateLockFile(Path lockFileDir) {
    if (!Files.isRegularFile(lockFileDir.resolve(lockFileName()))) {
      throw new IllegalStateException(
          String.format(
              "Lock file does not exist or is not supported. Execute '%s install' to generate it.",
              packageManager()));
    }
  }
}
