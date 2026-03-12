// Harness for Bug 5: UBSan signed-integer-overflow in parse_exponent().
//
// The SIMDJSON_NO_SANITIZE_UNDEFINED annotation was removed from parse_digit().
// parse_exponent() calls parse_digit() with an int64_t accumulator (exp_number).
// After 18 '9'-digits exp_number ~ 10^18; the 19th digit causes:
//   10 * 999999999999999999 + 9  (> INT64_MAX)  -> signed overflow -> UBSan
//
// The overflow guard (truncating at 18+ digits) runs AFTER the loop,
// so UBSan fires inside parse_digit on the 19th digit before the guard runs.
//
// Detected by: UBSan signed-integer-overflow
// Seed: 1e9999999999999999999  (19 nines in the exponent)
#include "simdjson.h"
#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  simdjson::dom::parser parser;
  simdjson::dom::element elem;
  auto error = parser.parse(Data, Size).get(elem);
  if (!error) {
    double d;
    int64_t i;
    uint64_t u;
    if (!elem.get_double().get(d)) { (void)d; }
    else if (!elem.get_int64().get(i)) { (void)i; }
    else if (!elem.get_uint64().get(u)) { (void)u; }
  }
  return 0;
}
