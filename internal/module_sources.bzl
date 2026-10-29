# *******************************************************************************
# Copyright (c) 2026 Contributors to the Eclipse Foundation
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License Version 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0
# *******************************************************************************

"""Read literal root-module Git overrides without evaluating Starlark."""

_SOURCE_FIELDS = [
    "module_name",
    "remote",
    "commit",
    "tag",
    "strip_prefix",
    "patches",
    "patch_args",
    "patch_cmds",
    "patch_cmds_win",
    "patch_tool",
    "patch_strip",
    "remote_patches",
    "remote_patch_strip",
]

def _tokens(content):
    tokens = []
    start = 0
    quote = ""
    escaped = False
    comment = False
    skip = 0
    word = ""
    for i in range(len(content)):
        if i < skip:
            continue
        c = content[i]
        if comment:
            if c == "\n":
                comment = False
                tokens.append("\n")
            continue
        if quote:
            if escaped:
                escaped = False
            elif c == "\\":
                escaped = True
            elif content[i:i + len(quote)] == quote:
                tokens.append(content[start:i + len(quote)])
                skip = i + len(quote)
                quote = ""
            continue
        if c.isalnum() or c == "_":
            word += c
            continue
        if word:
            tokens.append(word)
            word = ""
        if c == "#":
            comment = True
        elif c in ["'", '\"']:
            quote = c * 3 if content[i:i + 3] == c * 3 else c
            start = i
            skip = i + len(quote)
        elif c == "\n":
            tokens.append(c)
        elif not c.isspace():
            tokens.append(c)
    if quote:
        fail("Unterminated string in SBOM module input")
    if word:
        tokens.append(word)
    return tokens

def _string(token):
    raw = token.startswith(("r'", 'r"', "R'", 'R"'))
    if raw:
        token = token[1:]
    quote = token[0] * 3 if token.startswith(token[0] * 3) else token[0]
    body = token[len(quote):-len(quote)]
    if raw:
        return body
    result = []
    skip = 0
    escapes = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f", "a": "\a", "v": "\v", "\\": "\\", "'": "'", '"': '"'}
    digits = "0123456789abcdef"
    for i in range(len(body)):
        if i < skip:
            continue
        c = body[i]
        if c != "\\":
            result.append(c)
            continue
        if i + 1 >= len(body):
            return None
        escaped = body[i + 1]
        skip = i + 2
        if escaped in escapes:
            result.append(escapes[escaped])
        elif escaped == "\n":
            continue
        elif escaped == "x":
            value = body[i + 2:i + 4]
            if len(value) != 2 or any([c.lower() not in digits for c in value.elems()]):
                return None
            result.append(json.decode('"\\u00' + value + '"'))
            skip = i + 4
        elif escaped in "01234567":
            value = escaped
            for j in range(i + 2, min(i + 4, len(body))):
                if body[j] not in "01234567":
                    break
                value += body[j]
            number = int(value, 8)
            if number > 255:
                return None
            result.append(json.decode('"\\u00' + digits[number // 16] + digits[number % 16] + '"'))
            skip = i + 1 + len(value)
        else:
            return None
    return "".join(result)

def _literal(tokens, constants):
    # Decode data, constants and string concatenation; never execute expressions.
    # Parentheses around a literal are accepted by Bazel's include directive.
    for _ in range(len(tokens) // 2):
        if tokens[0] != "(" or tokens[-1] != ")":
            break
        depth = 0
        wraps = True
        for token in tokens[:-1]:
            if token == "(":
                depth += 1
            elif token == ")":
                depth -= 1
            if depth == 0:
                wraps = False
                break
        if not wraps:
            break
        tokens = tokens[1:-1]
    pieces = []
    pending = None
    concatenate = False
    skip = 0
    for i in range(len(tokens)):
        if i < skip:
            continue
        token = tokens[i]
        if token == "+" and pending != None:
            concatenate = True
            continue
        if token == "," and i + 1 < len(tokens) and tokens[i + 1] in ["]", "}"]:
            continue
        value = None
        if token in ["r", "R"] and i + 1 < len(tokens) and tokens[i + 1].startswith(("'", '"')):
            value = _string(token + tokens[i + 1])
            skip = i + 2
        elif token.startswith(("'", '"')):
            value = _string(token)
        elif token in constants:
            value = constants[token]
        if concatenate:
            if type(value) != "string":
                return None
            pending += value
            concatenate = False
            continue
        if pending != None:
            pieces.append(json.encode(pending))
            pending = None
        if type(value) == "string":
            pending = value
        elif value != None:
            pieces.append(json.encode(value))
        elif token in ["[", "]", "{", "}", ":", ",", "-"] or token.isdigit():
            pieces.append(token)
        else:
            return None
    if concatenate:
        return None
    if pending != None:
        pieces.append(json.encode(pending))
    return json.decode("".join(pieces), None)

def _split(tokens, separators):
    parts = []
    part = []
    depth = 0
    for token in tokens:
        if token in separators and depth == 0:
            if part:
                parts.append(part)
                part = []
            continue
        if token in ["(", "[", "{"]:
            depth += 1
        elif token in [")", "]", "}"]:
            depth -= 1
        if token != "\n":
            part.append(token)
    if part:
        parts.append(part)
    return parts

def parse_module_sources(content, filename):
    """Discover sources; unsupported expressions warn and retain partial evidence."""
    includes = []
    overrides = {}
    constants = {}
    for statement in _split(_tokens(content), ["\n", ";"]):
        if len(statement) >= 3 and statement[1] == "=":
            constants[statement[0]] = _literal(statement[2:], constants)
            continue
        if len(statement) < 3 or statement[0] not in ["include", "git_override"] or statement[1] != "(":
            continue
        arguments = _split(statement[2:-1], [","])
        if statement[0] == "include":
            label = _literal(arguments[0], constants) if arguments else None
            if type(label) == "string":
                includes.append(label)
            else:
                print("WARNING: {}: Cannot discover include label".format(filename))
                overrides[""] = {"unresolved_fields": ["include"]}
            continue
        attributes = {}
        unresolved = []
        for argument in arguments:
            if len(argument) < 3 or argument[1] != "=":
                unresolved.append("**kwargs")
                continue
            field = argument[0]
            if field not in _SOURCE_FIELDS:
                continue
            value = _literal(argument[2:], constants)
            if value == None:
                unresolved.append(field)
            else:
                attributes[field] = value
        name = attributes.pop("module_name", "")
        if unresolved or not name:
            print("WARNING: {}: Cannot resolve Git attributes {} for {}; source metadata may be incomplete".format(filename, unresolved, name or "unknown module"))
            attributes["unresolved_fields"] = unresolved or ["module_name"]

        # The empty key marks incomplete discovery (unknown module or include).
        # It is never used as a repository label.
        if name in overrides and name:
            fail("Duplicate Git override for " + name)
        overrides[name] = attributes
    return includes, overrides

def collect_git_overrides(module_ctx):
    """Follow root includes using watched reads, including files without BUILD."""
    root = module_ctx.path(Label("@@//:MODULE.bazel")).dirname
    pending = ["MODULE.bazel"]
    seen = {}
    result = {}

    # Starlark has neither recursion nor while loops. Bound traversal explicitly
    # and fail rather than return incomplete metadata if the bound is reached.
    for index in range(10000):
        if index >= len(pending):
            return result
        filename = pending[index]
        if filename in seen:
            continue
        seen[filename] = True
        includes, overrides = parse_module_sources(module_ctx.read(root.get_child(filename), watch = "yes"), filename)
        for name, override in overrides.items():
            if name in result and name:
                fail("Duplicate Git override for " + name)
            result[name] = override
        for label in includes:
            if not label.startswith("//") or ".." in label.split("/"):
                fail("Invalid root module include: " + label)
            parsed = Label("@@" + label)
            path = (parsed.package + "/" + parsed.name).lstrip("/")
            if path not in seen:
                pending.append(path)
    fail("SBOM module discovery exceeded 10000 included files")
