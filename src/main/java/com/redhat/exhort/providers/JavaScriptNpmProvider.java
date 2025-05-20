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

import com.redhat.exhort.tools.Ecosystem;
import java.nio.file.Path;

/**
 * Concrete implementation of the {@link JavaScriptProvider} used for converting dependency trees
 * for npm projects (package.json) into a SBOM content for Stack analysis or Component analysis.
 */
public final class JavaScriptNpmProvider extends JavaScriptProvider {

  public static final String LOCK_FILE = "package-lock.json";
  public static final String CMD_NAME = "npm";

  public JavaScriptNpmProvider(Path manifest) {
    super(manifest, Ecosystem.Type.NPM, CMD_NAME);
  }

  @Override
  protected final String lockFileName() {
    return LOCK_FILE;
  }

  @Override
  protected String[] updateLockFileCmd(Path manifestDir) {
    return new String[] {
      packageManager(), "i", "--package-lock-only", "--prefix", manifestDir.toString()
    };
  }

  @Override
  protected String[] listDepsCmd(boolean includeTransitive, Path manifestDir) {
    if (manifestDir != null) {
      return new String[] {
        packageManager(),
        "ls",
        includeTransitive ? "--all" : "--depth=0",
        "--omit=dev",
        "--package-lock-only",
        "--json",
        "--prefix",
        manifestDir.toString()
      };
    }
    return new String[] {
      packageManager(),
      "ls",
      includeTransitive ? "--all" : "--depth=0",
      "--omit=dev",
      "--package-lock-only",
      "--json"
    };
  }
}
