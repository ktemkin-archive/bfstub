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

#include "helpers.h"

extern "C" {
  #include <libfdt.h>
}


/**
 * Creates a new BinaryFile object, and awaits
 * later initialization (e.g. by an inheriting class.)
 */
BinaryFile::BinaryFile()
{

}


/**
 * Creates a new BinaryFile object.
 *
 * @param path The path to the file to be opened.
 */
BinaryFile::BinaryFile(const char * filename)
{
    // Open the provided file.
    std::ifstream file(filename, std::ios::binary | std::ios::ate);

    if(!file) {
        throw std::invalid_argument("Could not open file!");
    }

    // Determine the file's size...
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    // ... and adjust our internal vector so it has enough size
    // for the relevant data.
    this->data.resize(size);

    // Finally, populate the vector with our data.
    file.read(this->data.data(), size);

    if(!file) {
        throw std::runtime_error("Could not read from file!");
    }

}


/**
 * @return The total number of bytes in the file.
 */
size_t BinaryFile::size() {
    return this->data.size();
}

/**
 * A pointer to the raw data content of the file.
 */
void *BinaryFile::raw_bytes() {
    return this->data.data();
}


/**
 * Creates a new DeviceTree by reading the contents
 * of a local file.
 *
 * @param path The path to the file to be read.
 */
FlattenedTree::FlattenedTree(const char *path)
  : BinaryFile(path)
{

}


/**
 * Creates a new DeviceTree by copying an existing memory
 * buffer.
 *
 * @param fdt A pointer to the existing FDT in memory.
 */
FlattenedTree::FlattenedTree(const void *fdt)
{
    if(!fdt) {
        throw std::invalid_argument("Cannot create a flattened tree from NULL!");
    }

    // Read the total size of the FDT, and resize our buffer accordingly.
    size_t size = fdt_totalsize(fdt);
    this->data.resize(size);

    // Finally, copy the data into our buffer.
    memcpy(this->data.data(), fdt, size);
}


/**
 * Returns a pointer to the given property from within the FDT.
 *
 * @param node The node to read the given property from.
 * @param property The propery to be read.
 * @return A pointer to the raw data for the property inside the FDT.
 */
const void * FlattenedTree::find_property_location(const char *node, const char *property)
{
      // First, locate the relevant FDT node.
      int module_node = fdt_path_offset(this->data.data(), node);
      if(module_node < 0) {
          throw std::invalid_argument("Could not find the given node!");
      }

      // Locate the node that specifies where we should load this image from.
      int size;
      const void *data_location = fdt_getprop(this->data.data(), module_node, property,  &size);

      if(size <= 0) {
          throw std::invalid_argument("Could not read the given property!");
      }

      return data_location;
}


/**
 * Reads a string property from the given FDT.
 *
 * @param node The node to read the given property from.
 * @param property The propery to be read.
 */
std::string FlattenedTree::read_property_string(const char *node, const char *property, int offset) {

  char *location = (char *)find_property_location(node, property);

  //Skip the first offset strings.
  while(offset--) {
      location = (char *)rawmemchr(location, 0) + 1;
  }

  return std::string(location);
}


/**
 * Reads a uint64 property from the given FDT.
 *
 * @param node The node to read the given property from.
 * @param property The propery to be read.
 */
uint64_t FlattenedTree::read_property_u64(const char *node, const char *property, int offset) {

  fdt64_t *base_location = (fdt64_t *)find_property_location(node, property);
  fdt64_t *location = base_location + offset;

  return fdt64_to_cpu(*location);
}
