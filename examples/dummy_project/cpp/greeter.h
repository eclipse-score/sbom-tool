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
#ifndef EXAMPLES_DUMMY_PROJECT_CPP_GREETER_H
#define EXAMPLES_DUMMY_PROJECT_CPP_GREETER_H

#include <string>

namespace dummy {

// Returns a JSON document describing the greeting for `name`.
std::string Greet(const std::string& name);

}  // namespace dummy

#endif  // EXAMPLES_DUMMY_PROJECT_CPP_GREETER_H
