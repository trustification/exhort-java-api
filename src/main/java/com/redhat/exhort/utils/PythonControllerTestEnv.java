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
import java.nio.file.Path;

public class PythonControllerTestEnv extends PythonControllerRealEnv {

  public PythonControllerTestEnv(String pathToPythonBin, String pathToPip) {
    super(pathToPythonBin, pathToPip);
  }

  @Override
  public void prepareEnvironment(String pathToPythonBin) {
    super.prepareEnvironment(pathToPythonBin);
    Operations.runProcessGetOutput(
        Path.of("."),
        new String[] {this.pathToPythonBin, "-m", "pip", "install", "--upgrade", "pip"});
  }

  @Override
  public boolean automaticallyInstallPackageOnEnvironment() {
    return true;
  }

  @Override
  public boolean isVirtualEnv() {
    return false;
  }
}
