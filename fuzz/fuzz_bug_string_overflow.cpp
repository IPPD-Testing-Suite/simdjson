// Harness for Bug 2: ASan heap-buffer-overflow (write) in DOM string parsing.
//
// The DOM document::allocate() string buffer was reduced from 5*capacity/3
// to capacity/3.  For any JSON string whose decoded length exceeds capacity/3,
// parse_string() writes past the end of the allocated string_buf.
//
// Detected by: ASan heap-buffer-overflow (write)
// Seed: ["AAAA..."] (200+ ASCII characters inside a JSON string)
#include "simdjson.h"
#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  simdjson::dom::parser parser;
  simdjson::dom::element elem;
  auto error = parser.parse(Data, Size).get(elem);
  if (!error) {
    if (elem.is_string()) {
      std::string_view sv;
      if (!elem.get_string().get(sv)) { (void)sv; }
    } else if (elem.is_array()) {
      for (auto e : elem.get_array()) {
        std::string_view sv;
        if (!e.get_string().get(sv)) { (void)sv; }
      }
    } else if (elem.is_object()) {
      for (auto [key, val] : elem.get_object()) {
        (void)key;
        (void)val;
      }
    }
  }
  return 0;
}
