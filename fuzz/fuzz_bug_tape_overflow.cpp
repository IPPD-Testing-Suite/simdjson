// Harness for Bug 4: ASan heap-buffer-overflow (write) in DOM tape.
//
// document::allocate() tape capacity was reduced from (capacity+3) to
// (capacity/2+3).  For a deeply-nested input like [[[[...]]]], the tape
// writer needs one entry per structural character, but the halved allocation
// overflows after roughly capacity/2 tape writes.
//
// Example: 128 '[' + 128 ']' (256 bytes) needs 258 tape entries but only
// gets ROUNDUP(131, 64) = 192 slots.  ASan catches the write at tape[192].
//
// Detected by: ASan heap-buffer-overflow (write)
// Seed: [[[[...]]]] (128 '[' followed by 128 ']')
#include "simdjson.h"
#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  simdjson::dom::parser parser;
  simdjson::dom::element elem;
  auto error = parser.parse(Data, Size).get(elem);
  if (!error) {
    // Trigger tape traversal
    if (elem.is_array()) {
      simdjson::dom::array arr;
      if (!elem.get_array().get(arr)) { (void)arr; }
    }
  }
  return 0;
}
