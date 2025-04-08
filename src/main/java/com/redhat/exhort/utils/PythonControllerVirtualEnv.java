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
package com.redhat.exhort.utils;

import com.redhat.exhort.tools.Operations;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;

public class PythonControllerVirtualEnv extends PythonControllerBase {

  //  private System.Logger log = System.getLogger("name");
  public PythonControllerVirtualEnv(String pathToPythonBin) {
    this.pipBinaryDir =
        Path.of(FileSystems.getDefault().getSeparator(), "tmp", "exhort_env", "bin");
    this.pythonEnvironmentDir =
        Path.of(FileSystems.getDefault().getSeparator(), "tmp", "exhort_env");
    this.pathToPythonBin = pathToPythonBin;
  }

  @Override
  public void prepareEnvironment(String pathToPythonBin) {
    try {
      if (!Files.exists(pythonEnvironmentDir)) {
        Files.createDirectory(pythonEnvironmentDir);
      }
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
    Operations.runProcessGetOutput(
        Path.of("."),
        new String[] {pathToPythonBin, "-m", "venv", pythonEnvironmentDir.toString()});
    String envBinDir = pipBinaryDir.toString();
    if (pathToPythonBin.contains("python3")) {
      this.pipBinaryLocation = Path.of(envBinDir, "pip3").toString();
    } else {
      this.pipBinaryLocation = Path.of(envBinDir, "pip").toString();
    }
  }

  @Override
  public boolean automaticallyInstallPackageOnEnvironment() {
    return true;
  }

  @Override
  public boolean isRealEnv() {
    return false;
  }

  @Override
  public boolean isVirtualEnv() {
    return true;
  }

  @Override
  public void cleanEnvironment(boolean deleteEnvironment) {
    if (deleteEnvironment) {
      try {
        Files.walk(pythonEnvironmentDir)
            .sorted(Comparator.reverseOrder())
            .forEach(
                file -> {
                  try {
                    Files.delete(file);
                  } catch (IOException e) {
                    throw new RuntimeException(e);
                  }
                });
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
    } else {
      Path envRequirements = Path.of(pythonEnvironmentDir.toString(), "requirements.txt");
      try {
        Files.deleteIfExists(envRequirements);
        String freezeOutput =
            Operations.runProcessGetOutput(pythonEnvironmentDir, pipBinaryLocation, "freeze");
        Files.createFile(envRequirements);
        Files.write(envRequirements, freezeOutput.getBytes());
        Operations.runProcessGetOutput(
            pythonEnvironmentDir, pipBinaryLocation, "uninstall", "-y", "-r", "requirements.txt");

      } catch (IOException e) {
        throw new RuntimeException(e);
      }
    }
  }
}
