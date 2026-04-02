#!/bin/sh
#
# entry point for oss-fuzz, so that fuzzers
# and build invocation can be changed without having
# to modify the oss-fuzz repo.
#
# invoke it from the git root.

# make sure to exit on problems
set -eux

for prog in zip cmake ninja; do
    if ! which $prog >/dev/null; then
	echo please install $prog
	exit 1
    fi
done


# build the corpus (all inputs are json, the same corpus can be used for everyone)
fuzz/build_corpus.sh

rm -rf build
mkdir -p build
cd build

cmake .. \
-GNinja \
-DCMAKE_BUILD_TYPE=Debug \
-DSIMDJSON_DEVELOPER_MODE=ON \
-DBUILD_SHARED_LIBS=OFF \
-DSIMDJSON_ENABLE_FUZZING=On \
-DSIMDJSON_COMPETITION=Off \
-DSIMDJSON_FUZZ_LINKMAIN=Off \
-DSIMDJSON_GOOGLE_BENCHMARKS=Off \
-DSIMDJSON_DISABLE_DEPRECATED_API=On \
-DSIMDJSON_FUZZ_LDFLAGS=$LIB_FUZZING_ENGINE

cmake --build . --target all_fuzzers

# Build tests separately; allow failures since some tests are excluded
# at runtime in run_tests.sh (ondemand_cacheline, builder_string_builder_tests, etc.)
cmake --build . --target all_tests || true

cp fuzz/fuzz_* $OUT

# all fuzzers but one (the tiny target for utf8 validation) takes json
# as input, therefore use the same corpus of json files for all.
for f in $(ls $OUT/fuzz* |grep -v '.zip$') ; do
   cp ../corpus.zip $OUT/$(basename $f).zip
done

