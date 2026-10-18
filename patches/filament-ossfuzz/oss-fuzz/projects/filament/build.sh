#!/bin/bash -eu
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Filament is a renderer, but the fuzz targets only cover the asset parsers, which are pure CPU
# code. Everything that needs a GPU, a window system or a shader compiler is switched off so the
# build stays small and OSS-Fuzz does not need graphics drivers.

cd "$SRC/filament"

mkdir -p build
cd build

cmake .. \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER="$CC" \
    -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_C_FLAGS="$CFLAGS" \
    -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
    -DFILAMENT_ENABLE_FUZZERS=ON \
    -DFILAMENT_SKIP_SAMPLES=ON \
    -DFILAMENT_SKIP_SDL2=ON \
    -DFILAMENT_BUILD_TESTING=OFF \
    -DFILAMENT_SUPPORTS_VULKAN=OFF \
    -DFILAMENT_SUPPORTS_OPENGL=OFF \
    -DFILAMENT_ENABLE_LTO=OFF

FUZZERS="material_parser_fuzzer"

for fuzzer in $FUZZERS; do
    ninja "$fuzzer"
    find . -name "$fuzzer" -type f -perm -u+x -exec cp {} "$OUT/" \;
done

# Seed corpus. The materials checked into the repository are valid .filamat files, which gives
# libFuzzer a starting point that already passes the chunk-container and dictionary stages
# instead of having to rediscover the container format from scratch.
seed_dir="$WORK/material_parser_seeds"
rm -rf "$seed_dir"
mkdir -p "$seed_dir"

i=0
while IFS= read -r -d '' mat; do
    cp "$mat" "$seed_dir/seed_$i.filamat"
    i=$((i + 1))
done < <(find "$SRC/filament" -name '*.filamat' -type f -print0)

if [ "$i" -gt 0 ]; then
    zip -j -q "$OUT/material_parser_fuzzer_seed_corpus.zip" "$seed_dir"/*
fi
