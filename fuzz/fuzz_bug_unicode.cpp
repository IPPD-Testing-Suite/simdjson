// Harness for Bug 1: OOB read in hex_to_u32_nocheck via off-by-one in
// digit_to_val32 base index (630 -> 631).
//
// Trigger: a JSON string containing \u followed by a high byte (0xFF...).
// When src[0] == 0xFF the faulty index 631+255 = 886 reads one element
// past the end of the 886-element digit_to_val32 table.
//
// Detected by: ASan global-buffer-overflow (read)
// Seed: ["\u\xff\x30\x30\x30"]
#include "simdjson.h"
#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  simdjson::dom::parser parser;
  simdjson::dom::element elem;
  auto error = parser.parse(Data, Size).get(elem);
  if (!error) {
    // Walk strings to force unicode unescape code path
    if (elem.is_string()) {
      std::string_view sv;
      elem.get_string().get(sv);
    } else if (elem.is_array()) {
      for (auto e : elem.get_array()) {
        std::string_view sv;
        e.get_string().get(sv);
      }
    }
  }
  return 0;
}
