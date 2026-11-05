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

"""Remove URL credentials from published metadata without mutating source inputs."""

import re
import urllib.parse
from typing import Any

_SCHEME = r"[a-z][a-z0-9+.-]*"
# Apostrophes and query sub-delimiters are valid inside URL userinfo.
_USERINFO = r"(?:\\u[0-9a-f]{4}|[^\s<>\"\\/?#])*"
_LITERAL_AUTHORITY = re.compile(
    r"(?<![a-z0-9+.-])[a-z](?:[a-z0-9+.-]|%(?:25)*2b)*(?::|%(?:25)*3a)//"
    + _USERINFO
    + "@",
    re.IGNORECASE,
)
# Support full, partial and repeated quoting of URL delimiters. An encoded '@'
# without a literal authority separator can also hide partially quoted userinfo.
_ENCODED_URL = re.compile(
    r"[a-z](?:[a-z0-9+.-]|%(?:25)*2b)*"
    r"(?:%(?:25)*3a(?:/|%(?:25)*2f){2}"
    r"|:(?:%(?:25)*2f(?:/|%(?:25)*2f)|/%(?:25)*2f)"
    r"|://(?=[^/?#@]*(?:[/?#]|$))[^/?#@]*%(?:25)*40)"
    + "(?:"
    + _USERINFO
    + "(?:@|%(?:25)*40))?"
    + r"(?:\\u[0-9a-f]{4}|[^\s<>\"\\])+",
    re.IGNORECASE,
)
_URL = re.compile(
    r"(?<![a-z0-9+.-])(?:"
    + _ENCODED_URL.pattern
    + "|"
    + r"(?:"
    + _SCHEME
    + r"://(?:"
    + _USERINFO
    + r"@)?|pkg:)(?:\\u[0-9a-f]{4}|[^\s<>\"\\])+)",
    re.IGNORECASE,
)
_AUTH_HEADER = re.compile(
    r"(\b(?:proxy-)?authorization\s*:\s*(?:basic|bearer|token)\s+)[^\s\"'\\,;]+",
    re.IGNORECASE,
)
_MAX_URL_DEPTH = 16
_SECRET_KEYS = {
    "token",
    "accesstoken",
    "refreshtoken",
    "idtoken",
    "privatetoken",
    "auth",
    "authorization",
    "password",
    "passwd",
    "apikey",
    "key",
    "secret",
    "clientsecret",
    "credential",
    "credentials",
    "signature",
    "sig",
    "xamzcredential",
    "xamzsignature",
    "xamzsecuritytoken",
    "xgoogcredential",
    "xgoogsignature",
    "xgoogsecuritytoken",
}


def _redact_parameters(parameters: str, depth: int) -> str:
    parts = []
    for part in parameters.split("&"):
        if _URL.match(part):
            parts.append(_redact_text(part, depth + 1))
            continue
        key, separator, value = part.partition("=")
        normalized = re.sub(r"[-_]", "", urllib.parse.unquote_plus(key)).lower()
        if separator and (
            normalized in _SECRET_KEYS
            or normalized.endswith(
                ("token", "password", "secret", "signature", "credential", "apikey")
            )
        ):
            part = key + "=REDACTED"
        elif separator:
            part = key + "=" + _redact_value(value, depth + 1)
        parts.append(part)
    return "&".join(parts)


def _redact_userinfo(url: str) -> str:
    # Encoded password delimiters must not become URL boundaries before removal.
    authority = re.match(
        r"^([a-z](?:[a-z0-9+.-]|%(?:25)*2b)*(?::|%(?:25)*3a)(?:/|%(?:25)*2f){2})"
        r"([^/?#]*)(@|%(?:25)*40)",
        url,
        re.IGNORECASE,
    )
    if not authority:
        return url
    prefix, userinfo, separator = authority.groups()
    if not prefix.endswith("//"):
        # Fully quoted URLs need their encoded path/query boundaries decoded
        # together. A literal path boundary identifies a mixed-encoding URL.
        boundary = re.search(r"[/?#]", url[authority.end() :])
        if not boundary or boundary.group() != "/":
            return url
    if re.match(r"^(?:git(?:\+|%(?:25)*2b))?ssh(?::|%)", prefix, re.IGNORECASE):
        username = re.split(r":|%(?:25)*3a", userinfo, maxsplit=1, flags=re.IGNORECASE)[
            0
        ]
        prefix += username + separator
    return prefix + url[authority.end() :]


def _redact_url(url: str, depth: int) -> str:
    # Strip authority credentials before parsing: malformed hosts must not leak.
    url = _redact_userinfo(url)
    base, marker, fragment = url.partition("#")
    path, query_marker, query = base.partition("?")
    # An outer URL must not hide a URL embedded in its path either.
    path_start = (
        4 if path.lower().startswith("pkg:") else path.find("/", path.find("://") + 3)
    )
    if path_start >= 0:
        path = path[:path_start] + _redact_text(path[path_start:], depth + 1)
    return (
        path
        + (query_marker + _redact_parameters(query, depth) if query_marker else "")
        + (marker + _redact_parameters(fragment, depth) if marker else "")
    )


def _redact_value(value: str, depth: int) -> str:
    if depth >= _MAX_URL_DEPTH:
        return "REDACTED"
    value = _redact_userinfo(value)
    decoded = urllib.parse.unquote(value)
    redacted = _redact_text(decoded, depth + 1)
    if decoded == value:
        return redacted
    # Inspect remaining encoding after removing credentials at this level.
    # Unchanged escapes (including URL paths) retain their original spelling.
    if "%" in redacted:
        redacted = _redact_value(redacted, depth + 1)
    return urllib.parse.quote(redacted, safe="") if redacted != decoded else value


def _redact_text(value: str, depth: int = 0) -> str:
    # Bound nested URL/encoding recursion; do not publish an unchecked value.
    if depth >= _MAX_URL_DEPTH:
        return "REDACTED"

    def redact(match):
        original = match.group()
        suffix = ""
        # Apostrophes inside a URI are data; preserve an enclosing quote only
        # when the URL itself was introduced by a quote in the surrounding text.
        if match.start() and value[match.start() - 1] == "'":
            closing = re.search(r"'[),.;:!?\]}]*$", original)
            if closing:
                suffix = closing.group()
                original = original[: closing.start()]
        if not _ENCODED_URL.match(original):
            return _redact_url(original, depth) + suffix
        return _redact_value(original, depth) + suffix

    # Remove userinfo before quotes or '&' split surrounding text/parameters.
    # Encoded '@' separators must remain available to the staged URL decoder.
    value = _LITERAL_AUTHORITY.sub(lambda match: _redact_userinfo(match.group()), value)
    # Handle each outer URL before inspecting its nested values.
    value = _URL.sub(redact, value)
    return _AUTH_HEADER.sub(r"\1REDACTED", value)


def redact_credentials(value: Any) -> Any:
    """Redact URL userinfo and known authentication parameters in output copies.

    SSH usernames are retained because they distinguish home-relative paths;
    other URI schemes omit userinfo. Raw inputs/caches remain private source
    evidence; do not use redacted text or dictionaries for source comparison.
    """
    if isinstance(value, str):
        return _redact_text(value)
    if isinstance(value, list):
        return [redact_credentials(item) for item in value]
    if isinstance(value, dict):
        # SBOM keys are schema field names, not source URLs. Do not collapse keys
        # in raw maps (e.g. two authenticated patch URLs); render those as notes.
        return {key: redact_credentials(item) for key, item in value.items()}
    return value
