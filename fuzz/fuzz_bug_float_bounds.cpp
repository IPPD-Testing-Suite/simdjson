// Harness for Bug 3: ASan heap/global-buffer-overflow (read) in
// compute_float_64() via missing smallest_power lower-bound check.
//
// write_float() previously guarded: exponent < smallest_power (-342).
// The bug changes this to: exponent < smallest_power - 1 (-343).
// For input "1e-343", exponent == -343 bypasses the guard and reaches
// compute_float_64(-343, ...), which computes:
//   index = 2 * uint32_t(-343 - (-342)) = 2 * 0xFFFFFFFF = 8589934590
// This is a massive OOB read into power_of_five_128[].
//
// Detected by: ASan heap/global-buffer-overflow (read)
// Seed: 1e-343
#include "simdjson.h"
#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  simdjson::dom::parser parser;
  simdjson::dom::element elem;
  auto error = parser.parse(Data, Size).get(elem);
  if (!error) {
    double d;
    if (!elem.get_double().get(d)) {
      (void)d;
    }
  }
  return 0;
}
