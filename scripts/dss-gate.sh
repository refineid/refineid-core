#!/bin/sh
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
#
# The independent validation gate: sign every document format the core
# writes, as a release build signs it, and have the EU DSS library judge
# each one (crates/doc-sign/tests/dss_gate.rs). Run by the pre-push
# floor (scripts/verify-push.sh); run it by hand the same way:
#
#   sh scripts/dss-gate.sh [test name filter]
#
# The DSS release is pinned in tools/dss-gate/dss.lock: every jar is
# fetched once from Maven Central into the cache and refused unless its
# SHA-256 matches the lock. Once the cache holds them, the gate needs no
# network: the tests answer every TSA, OCSP, CRL and CA Issuers request
# in memory, and DSS runs with no online source.
#
# Environment:
#   REFINEID_DSS_CACHE  where the jars live (default
#                       ${XDG_CACHE_HOME:-$HOME/.cache}/refineid/dss-gate)
#   JAVA_HOME           a JDK 17 or later; otherwise found as below
set -eu

root=$(git rev-parse --show-toplevel)
cd "$root"

# Hooks may run from GUI clients whose PATH lacks the rustup shims.
if command -v brew > /dev/null 2>&1; then
    rustup_bin="$(brew --prefix rustup 2> /dev/null)/bin"
    if [ -d "$rustup_bin" ]; then
        PATH="$rustup_bin:$HOME/.cargo/bin:$PATH"
        export PATH
    fi
fi

lock="$root/tools/dss-gate/dss.lock"
source_file="$root/tools/dss-gate/DssGate.java"
cache="${REFINEID_DSS_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/refineid/dss-gate}"
central="https://repo1.maven.org/maven2"

fail() {
    echo "dss-gate: $*" >&2
    exit 1
}

sha256() {
    if command -v sha256sum > /dev/null 2>&1; then
        sha256sum "$1" | cut -d ' ' -f 1
    else
        shasum -a 256 "$1" | cut -d ' ' -f 1
    fi
}

# A JDK whose java and javac both run.
jdk_bin() {
    for candidate in \
        "${JAVA_HOME:-}" \
        "$(/usr/libexec/java_home 2> /dev/null || true)" \
        "$(brew --prefix openjdk 2> /dev/null || true)" \
        "$(dirname "$(dirname "$(command -v javac 2> /dev/null || echo /nonexistent/bin/javac)")")"; do
        if [ -n "$candidate" ] && "$candidate/bin/java" -version > /dev/null 2>&1 \
            && "$candidate/bin/javac" -version > /dev/null 2>&1; then
            echo "$candidate/bin"
            return 0
        fi
    done
    return 1
}

bin=$(jdk_bin) || fail "no JDK found: install a JDK 17 or later or set JAVA_HOME"

mkdir -p "$cache"
classpath=""
while read -r digest coordinates; do
    case "$digest" in '' | '#'*) continue ;; esac
    group=$(echo "$coordinates" | cut -d : -f 1)
    artifact=$(echo "$coordinates" | cut -d : -f 2)
    version=$(echo "$coordinates" | cut -d : -f 3)
    jar="$cache/$artifact-$version.jar"
    if [ ! -f "$jar" ] || [ "$(sha256 "$jar")" != "$digest" ]; then
        url="$central/$(echo "$group" | tr . /)/$artifact/$version/$artifact-$version.jar"
        echo "dss-gate: fetching $coordinates"
        curl -fsSL -o "$jar.part" "$url" || fail "cannot fetch $url"
        if [ "$(sha256 "$jar.part")" != "$digest" ]; then
            rm -f "$jar.part"
            fail "$coordinates does not match its SHA-256 in tools/dss-gate/dss.lock"
        fi
        mv "$jar.part" "$jar"
    fi
    classpath="$classpath:$jar"
done < "$lock"
classpath=${classpath#:}

classes="$root/target/dss-gate/classes"
rm -rf "$classes"
mkdir -p "$classes"
"$bin/javac" -nowarn -d "$classes" -cp "$classpath" "$source_file"

REFINEID_DSS_JAVA="$bin/java" \
REFINEID_DSS_CLASSPATH="$classes:$classpath" \
    cargo test -p refineid-doc-sign --features testkit --test dss_gate -- "$@"
echo "dss-gate: every format run reached B-LTA in DSS"
