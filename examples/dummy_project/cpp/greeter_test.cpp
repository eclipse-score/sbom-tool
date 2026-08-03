/********************************************************************************
 * Copyright (c) 2026 Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/
#include "cpp/greeter.h"

#include <cstdlib>
#include <iostream>
#include <string>

int main() {
  const std::string actual = dummy::Greet("SBOM");
  const std::string expected = R"({"greeting":"Hello, SBOM!","language":"cpp"})";
  if (actual != expected) {
    std::cerr << "expected: " << expected << "\n"
              << "actual:   " << actual << std::endl;
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
