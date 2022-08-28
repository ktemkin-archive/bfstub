/**
 * Tests helpers for testing discharge.
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

#include <vector>
#include <cstdlib>
#include <fstream>

/**
 * Simple class that provides scoped-duration access to a binary file
 * in a C-friendly way. Mostly syntactic sugar.
 */
class BinaryFile {

  public:

      /**
       * Creates a new BinaryFile object.
       *
       * @param path The path to the file to be opened.
       */
      BinaryFile(const char *path);

      /**
       * Creates a new BinaryFile object, and awaits
       * later initialization (e.g. by an inheriting class.)
       */
      BinaryFile();


      /**
       * @return The total number of bytes in the file.
       */
      size_t size();

      /**
       * @return a pointer to the raw data content of the file.
       */
      void *raw_bytes();

      /**
       * @return a pointer to the raw data content of the file.
       */
      operator void*();
      operator char*();

  protected:
      std::vector<char> data;
};


/**
 * Simple helper class for reading Flattened (Device/Image) Tree properties.
 */
class FlattenedTree : public BinaryFile {

    public:

      /**
       * Creates a new DeviceTree by reading the contents
       * of a local file.
       *
       * @param path The path to the file to be read.
       */
      FlattenedTree(const char *path);


      /**
       * Creates a new DeviceTree by copying an existing memory
       * buffer.
       *
       * @param fdt A pointer to the existing FDT in memory.
       */
      FlattenedTree(const void *fdt);


      /**
       * Reads a string property from the given FDT.
       *
       * @param node The node to read the given property from.
       * @param property The propery to be read.
       * @param position If provided, this will be considered the index into an
       *    array of strings; 0 would indicate the firststring, while e.g.
       *    1 would indicate the second.
       */
      std::string read_property_string(const char *node, const char *property, int position = 0);


      /**
       * Reads a uint64 property from the given FDT.
       *
       * @param node The node to read the given property from.
       * @param property The propery to be read.
       * @param position If provided, this will be considered the index into an
       *    array of uint64s; 0 would indicate the firststring, while e.g.
       *    1 would indicate the second.
       */
      uint64_t read_property_u64(const char *node, const char *property, int position = 0);


    protected:

      /**
       * Returns a pointer to the given property from within the FDT.
       *
       * @param node The node to read the given property from.
       * @param property The propery to be read.
       * @return A pointer to the raw data for the property inside the FDT.
       */
      const void * find_property_location(const char* node, const char *property);

};
