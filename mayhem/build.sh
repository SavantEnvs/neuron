#!/usr/bin/env bash
# Builds the neuron parsers (JSON REST/plugin-config decoders, CID/TPY/EDE file parsers, base64, the
# Modbus frame parser) with sanitizers, links six libFuzzer harnesses (+ -standalone reproducers), and
# builds the oracle with normal flags.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
M="$SRC/mayhem"

# Only the parser sources are compiled (not the full CMake build, which pulls NanoSDK/nng/mbedtls/
# libjwt/protobuf-c via git submodules/FetchContent); they need only jansson, libxml2 and openssl.
SRCS="src/parser/neu_json_cert.c src/parser/neu_json_cid.c src/parser/neu_json_driver.c
 src/parser/neu_json_error.c src/parser/neu_json_fn.c src/parser/neu_json_global_config.c
 src/parser/neu_json_group_config.c src/parser/neu_json_log.c src/parser/neu_json_login.c
 src/parser/neu_json_mqtt.c src/parser/neu_json_node.c src/parser/neu_json_otel.c
 src/parser/neu_json_plugin.c src/parser/neu_json_rw.c src/parser/neu_json_scan.c
 src/parser/neu_json_tag.c src/utils/json.c src/utils/cid.c src/utils/tpy.c src/utils/ede.c
 src/utils/base64.c src/utils/neu_path.c src/base/tag.c src/base/property.c
 plugins/mqtt/schema.c plugins/ekuiper/json_rw.c"
# The Modbus driver's frame and tag-address parsers (plugins/modbus), without its connection layer
# (fuzz_modbus.c includes modbus_req.c itself; its neu_conn/neu_event users are dropped by --gc-sections).
MB_SRCS="plugins/modbus/modbus.c plugins/modbus/modbus_point.c plugins/modbus/modbus_stack.c
 src/base/tag_sort.c"
export PKG_CONFIG_PATH="/opt/toolchains/deps/jansson-neugates/lib/pkgconfig:/opt/toolchains/deps/jansson-neugates/lib64/pkgconfig:${PKG_CONFIG_PATH:-}"
INC="-I$SRC/include/neuron -I$SRC/include -I$SRC/src -I$SRC/src/parser -I$SRC/plugins/modbus -I$SRC/plugins/mqtt -I$SRC/plugins/ekuiper -I$M/stubs $(pkg-config --cflags libxml-2.0 jansson)"
LIBS="$(pkg-config --libs libxml-2.0 jansson) -lcrypto -lzlog -lpthread -lm"

compile_objs() { # <outdir> <flags...>
  local out="$1"; shift
  mkdir -p "$out"
  for f in $SRCS; do
    "$CC" "$@" -std=gnu99 -c $INC "$SRC/$f" -o "$out/$(basename "$f" .c).o"
  done
}

# 1) sanitized fuzz objects
FUZZ_OUT="$M/build-fuzz"
compile_objs "$FUZZ_OUT" $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link

"$CXX" $SANITIZER_FLAGS $DEBUG_FLAGS -c "$M/lsan_off.cc" -o "$FUZZ_OUT/lsan_off.o"

# The Modbus objects are built with per-function sections so the linker can drop the unused I/O layer.
MBOBJS=""
for f in $MB_SRCS; do
  "$CC" $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -ffunction-sections -fdata-sections \
      -std=gnu99 -c $INC "$SRC/$f" -o "$FUZZ_OUT/mb_$(basename "$f" .c).o"
  MBOBJS="$MBOBJS $FUZZ_OUT/mb_$(basename "$f" .c).o"
done

# 2) harnesses: fuzzer + standalone
LIBOBJS=""; for f in $SRCS; do LIBOBJS="$LIBOBJS $FUZZ_OUT/$(basename "$f" .c).o"; done
for t in fuzz_json_rest fuzz_cid fuzz_tpy fuzz_ede fuzz_base64 fuzz_modbus; do
  OBJS="$LIBOBJS"; CFLAGS_T=""; LDFLAGS_T=""
  case "$t" in
    fuzz_base64) OBJS="$FUZZ_OUT/base64.o" ;;
    fuzz_modbus) OBJS="$MBOBJS $FUZZ_OUT/tag.o $FUZZ_OUT/property.o"
                 CFLAGS_T="-ffunction-sections -fdata-sections"
                 LDFLAGS_T="-fuse-ld=lld -Wl,--no-export-dynamic -Wl,--gc-sections" ;;
  esac
  "$CC" $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link $CFLAGS_T -std=gnu99 -c $INC "$M/$t.c" -o "$FUZZ_OUT/$t.o"
  "$CXX" $SANITIZER_FLAGS $DEBUG_FLAGS $LDFLAGS_T $LIB_FUZZING_ENGINE "$FUZZ_OUT/$t.o" $OBJS \
      "$FUZZ_OUT/lsan_off.o" $LIBS -o "$SRC/$t"
  "$CC" $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$FUZZ_OUT/standalone_main.o"
  "$CXX" $SANITIZER_FLAGS $DEBUG_FLAGS $LDFLAGS_T "$FUZZ_OUT/standalone_main.o" "$FUZZ_OUT/$t.o" $OBJS \
      "$FUZZ_OUT/lsan_off.o" $LIBS -o "$SRC/$t-standalone"
done

# 3) oracle: the same sources with the project's NORMAL flags (no sanitizers, no coverage), linked into
#    a dynamically linked known-answer probe that mayhem/test.sh runs.
ORACLE_OUT="$M/build-oracle"
compile_objs "$ORACLE_OUT" -O1 -g $COVERAGE_FLAGS
OOBJS=""; for f in $SRCS; do OOBJS="$OOBJS $ORACLE_OUT/$(basename "$f" .c).o"; done
"$CC" -O1 -g $COVERAGE_FLAGS -std=gnu99 -DTPY_EXPECTED_TAGS=20 $INC "$M/kat.c" $OOBJS $LIBS \
    -o "$ORACLE_OUT/kat"
