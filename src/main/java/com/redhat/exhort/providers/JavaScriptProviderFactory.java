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

import com.redhat.exhort.Provider;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.function.Function;

public final class JavaScriptProviderFactory {

  private static final Map<String, Function<Path, Provider>> JS_PROVIDERS =
      Map.of(
          JavaScriptNpmProvider.LOCK_FILE, (manifest) -> new JavaScriptNpmProvider(manifest),
          JavaScriptYarnProvider.LOCK_FILE, (manifest) -> new JavaScriptYarnProvider(manifest),
          JavaScriptPnpmProvider.LOCK_FILE, (manifest) -> new JavaScriptPnpmProvider(manifest));

  public static Provider create(final Path manifestPath) {
    var manifestDir = manifestPath.getParent();
    for (var entry : JS_PROVIDERS.entrySet()) {
      var lockFilePath = manifestDir.resolve(entry.getKey());
      if (Files.isRegularFile(lockFilePath)) {
        return entry.getValue().apply(manifestPath);
      }
    }
    var validLockFiles = String.join(",", JS_PROVIDERS.keySet());
    throw new IllegalStateException(
        String.format(
            "No known lock file found for %s. Supported lock files: %s",
            manifestPath, validLockFiles));
  }
}
