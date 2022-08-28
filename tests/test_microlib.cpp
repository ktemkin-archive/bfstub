/**
 * Tests for the Discharge microlib "standard library" subsection.
 *
 * Copyright (C) 2016 Assured Information Security, Inc.
 *      Author: ktemkin <temkink@ainfosec.com>
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a 
 *  copy of this software and associated documentation files (the "Software"), 
 *  to deal in the Software without restriction, including without limitation 
 *  the rights to use, copy, modify, merge, publish, distribute, sublicense, 
 *  and/or sell copies of the Software, and to permit persons to whom the 
 *  Software is furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in 
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS 
 *  OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
 *  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
 *  DEALINGS IN THE SOFTWARE.
 */

#include "catch.hpp"
#include <include/microlib.h>


SCENARIO("using the microlib implementation of memcpy", "[memcpy]") {
    int source[12];
    int destination[12] = {0};
    int i;

    for(i = 0; i < 12; ++i) {
        source[i] = i;
    }

    // Copy the first ten elements of the array.
    WHEN("a copy of the ten elements is performed") {
        memcpy(destination, source, sizeof(int) * 10);


        THEN("the first ten elements are copied") {
            for(i = 0; i < 10; ++i) {
                REQUIRE(destination[i] == source[i]);
            }
        }

        THEN("elements past the memcpy are not affected") {
            REQUIRE(destination[10] == 0);
            REQUIRE(destination[11] == 0);
        }
    }

}


SCENARIO("using the microlib implementation of memmove", "[memmove]") {

  WHEN("buffers don't overlap") {
      AND_WHEN("a copy of ten elements is performed") {

          int source[12];
          int destination[12] = {0};
          int i;

          for(i = 0; i < 12; ++i) {
              source[i] = i;
          }

          // Copy the first ten elements of the array.
          memmove(destination, source, sizeof(int) * 10);

          THEN("the first ten elements are copied") {
              for(i = 0; i < 10; ++i)
                REQUIRE(destination[i] == source[i]);
          }

          THEN("elements past the move are not affected") {
              REQUIRE(destination[10] == 0);
              REQUIRE(destination[11] == 0);
          }
      }
  }


  WHEN("buffers overlap") {
      AND_WHEN("a move of ten elements is performed") {

          int buffer[12] = {0};
          int i;

          for(i = 0; i < 10; ++i) {
              buffer[i] = i;
          }

          // Move each element one into the array.
          memmove(buffer + 1, buffer, sizeof(int) * 10);

          THEN("the first ten elements are moved") {
              for(i = 0; i < 10; ++i)
                REQUIRE(buffer[i + 1] == i);
          }

          THEN("elements past the memcpy are not affected") {
              REQUIRE(buffer[11] == 0);
          }
      }
  }

}

// Note: for now, we're not unit testing putc/puts. puts should be filled in if
// we adopt hippomocks, and should be interpreted as a sequence of calls to putc.

SCENARIO("when using the microlib implementation of strlen", "[strlen]") {
    WHEN("provided a null-terminated string") {
        THEN("strlen returns its length, not including the null") {
            REQUIRE(strlen("") == 0);
            REQUIRE(strlen("Hello\0there") == 5);
            REQUIRE(strlen("Hello, there.") == 13);
        }
    }
}

SCENARIO("when using the microlib implementation of memcmp", "[memcmp]") {
    char first[] = "hello world";
    char second[] = "hello, new york";

    WHEN("two relevant memory regions differ") {
        AND_WHEN("the first string contains a lesser byte") {
            THEN("memcmp returns a negative result") {
                REQUIRE(memcmp(first, second, 11) < 0);
            }
        }
        AND_WHEN("the second string contains a lesser byte") {
            THEN("memcmp returns a positive result") {
                REQUIRE(memcmp(second, first, 11) > 0);
            }
        }
    }

    WHEN("the two memory regions are the same") {
      THEN("memcmp returns zero") {
          REQUIRE(memcmp(first, second, 5) == 0);
      }
    }
}


SCENARIO("when using the microlib implementation of strnlen", "[strnlen]") {
    WHEN("provided a string shorter than the limit") {
        THEN("strlen returns its length, not including the null") {
            REQUIRE(strnlen("", 25) == 0);
            REQUIRE(strnlen("Hello\0there", 25) == 5);
            REQUIRE(strnlen("Hello, there.", 25) == 13);
        }
    }

    WHEN("provided a string longer than the limit") {
        THEN("strlen returns the limit") {
            REQUIRE(strnlen("Hello\0there", 3) == 3);
            REQUIRE(strnlen("Hello, there.", 10) == 10);
        }
    }
}

SCENARIO("when using the microlib implementation of memchr", "[memchr]") {
    uint8_t bytes[] = {0x00, 0xFF, 0xAA, 0xBB, 0xCC, 0x00, 0xDD};

    WHEN("provided a buffer containing a target byte") {
        THEN("memchr returns a pointer to the first location of the target byte") {
            REQUIRE(memchr(bytes, 0x00, sizeof(bytes)) == bytes + 0);
            REQUIRE(memchr(bytes, 0xFF, sizeof(bytes)) == bytes + 1);
            REQUIRE(memchr(bytes, 0xAA, sizeof(bytes)) == bytes + 2);
            REQUIRE(memchr(bytes, 0xDD, sizeof(bytes)) == bytes + 6);
        }
    }

    WHEN("provided a buffer that does not contain a target byte") {
        THEN("memchr returns NULL") {
            REQUIRE(memchr(bytes, 0x88, sizeof(bytes)) == NULL);
            REQUIRE(memchr(bytes, 0xDD, 3) == NULL);
        }
    }
}


SCENARIO("when using the microlib implementation of memset", "[memset]") {
    int buffer[12];
    int i;

    for(i = 0; i < 12; ++i) {
        buffer[i] = i;
    }

    WHEN("asked to clear a set of elements") {
        memset(buffer + 1, 0x0A, 10 * sizeof(int));

        THEN("each of the relevant elements is affected") {
            for(i = 1; i < 11; ++i) {
              REQUIRE(buffer[i] == 0x0A0A0A0A);
            }
        }

        THEN("elements before and after the set aren't affected") {
            REQUIRE(buffer[0] == 0);
            REQUIRE(buffer[11] == 11);
        }
    }
}
