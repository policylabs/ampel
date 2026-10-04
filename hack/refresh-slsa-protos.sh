#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
# SPDX-License-Identifier: Apache-2.0

# 
# This script refreshes the SLSA protos from the latest versions in 
# the SLSA repository.

set -e

TMP_DIR=$(mktemp -d )

git clone --depth=1 https://github.com/slsa-framework/slsa.git "$TMP_DIR"

cp "${TMP_DIR}/docs/spec/v1.0/schema/provenance.proto" proto/slsa/v10/provenance-v1.0.0.proto
cp "${TMP_DIR}/docs/spec/v1.1/schema/provenance.proto" proto/slsa/v11/provenance-v1.1.0.proto

# Rename the proto package names
sed -i 's/package slsa.v1;/package slsa.v11;/' proto/slsa/v11/provenance-v1.1.0.proto

sed -i 's/syntax = "proto3";/syntax = "proto3";\noption go_package = "github.com\/carabiner-dev\/ampel\/pkg\/formats\/predicate\/slsa\/provenance\/v10";/' proto/slsa/v10/provenance-v1.0.0.proto
sed -i 's/syntax = "proto3";/syntax = "proto3";\noption go_package = "github.com\/carabiner-dev\/ampel\/pkg\/formats\/predicate\/slsa\/provenance\/v11";/' proto/slsa/v11/provenance-v1.1.0.proto

rm -rf "$TMP_DIR"
