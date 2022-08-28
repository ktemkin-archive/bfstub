/**
 * Tests for the image-loading components of 
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

#include "test_case.h"

extern "C" {
  #include <image.h>
  #include <cache.h>
}

// The location of the test FIT image to use for image tests.
const char * test_image = "assets/image_test.fit";

// The location of the test FDT to use for loading kernel objects.
const char * test_fdt = "assets/test_fdt.dtb";

SCENARIO("using ensure_image_is_accessible to validate an FDT", "[ensure_image_is_accessible]") {

    WHEN("a valid image is provided") {
        BinaryFile image_file(test_image);
        void * image = image_file.raw_bytes();

        THEN("ensure_image_is_accessible returns SUCCESS") {
            REQUIRE(ensure_image_is_accessible(image) == SUCCESS);
        }

        THEN("ensure_image_is_accessible invalidates all cache lines for the image") {
            MockRepository mocks;

            mocks.ExpectCallFunc(__invalidate_cache_region).With(image, image_file.size());
            ensure_image_is_accessible(image);
        }
    }

    WHEN("an invalid image is provided") {
        int * image = (int *)malloc(1024);
        image[0] = 0xDEADBEEF;

        THEN("ensure_image_is_accessible returns an error code") {
            REQUIRE(ensure_image_is_accessible(image) != SUCCESS);
        }
    }
}


SCENARIO("using get_subcomponent_information to read kernel information", "[get_subcomponent_information]") {
    BinaryFile image_file(test_image);
    void * image = image_file.raw_bytes();

    const void * data_location;
    void *load_location;
    int size, offset, rc;

    WHEN("reading the location of the Xen kernel from the test image, providing all parameters") {
        rc = get_subcomponent_information(image, "/images/xen_kernel@1", &load_location, &data_location,
            &size, &offset);

        THEN("the load location matches the FIT property") {
            REQUIRE(load_location == (void *)0x80100000);
        }
        THEN("the size matches the size of the demo Xen kernel") {
            REQUIRE(size == 788336);
        }
        THEN("the data location matches the offset of the Xen blob in the FDT") {
            REQUIRE(data_location == (char *)image + 196);
        }
        THEN("the node offset matches the offset of the relevant node in the FDT") {
            REQUIRE(offset == 80);
        }
        THEN("the return code is success") {
            REQUIRE(rc == SUCCESS);
        }
    }

    WHEN("reading the location of the Xen kernel, omitting the offset") {
        rc = get_subcomponent_information(image, "/images/xen_kernel@1", &load_location, &data_location,
            &size, NULL);

        THEN("the function invocation still succeeds") {
            REQUIRE(rc == SUCCESS);
        }
    }

    WHEN("reading an invalid path from the test image") {
        rc = get_subcomponent_information(image, "/images/junk_addr@0", &load_location, &data_location,
            &size, &offset);

        THEN("the return code is not success") {
            REQUIRE(rc != SUCCESS);
        }
    }
}

static char mock_load_target_component_case[32];
static char mock_data_source_component_case[32];

/**
 * Mock version of the get_subcomponent_information function that enables
 * testing of the component loading functions.
 */
int mock_get_subcomponent_information_component_case(const void *image, const char *path,
    void **out_load_location, void const**out_data_location, int *out_size,
    int * node_offset) {

    //Populate our mock source with some interesting data.
    for(int i; i < 32; ++i) {
        mock_data_source_component_case[i] = i;
        mock_load_target_component_case[i] = 0;
    }

    *out_load_location = mock_load_target_component_case;
    *out_data_location = mock_data_source_component_case;
    *out_size = 16;

    return SUCCESS;
}

SCENARIO("using load_image_component to load a FIT component", "[load_image_component]") {

    WHEN("loading a valid kernel into memory") {
        int size;

        // Ensure that we use our mock get_subcomponent_information instead of the real one.
        MockRepository mocks;
        mocks.ExpectCallFunc(get_subcomponent_information).Do(mock_get_subcomponent_information_component_case);

        char * result = (char *)load_image_component(NULL, NULL, &size);

        THEN("the function returns a pointer to image-specified load address") {
            REQUIRE(result == mock_load_target_component_case);
        }
        THEN("the function correctly indicates the size of the loaded kernel") {
            REQUIRE(size == 16);
        }
        THEN("the kernel is loaded to the given address") {
            for(int i = 0; i < 16; ++ i) {
                REQUIRE(result[i] == mock_data_source_component_case[i]);
            }
        }
        THEN("no memory is affected is affected past the extent of the load") {
            for(int i = 16; i < 32; ++ i) {
                REQUIRE(result[i] == 0);
            }
        }
    }

    WHEN("requesting the load of an invalid kernel path") {
        int size = 0xAA;

        // Ensure that we use our mock get_subcomponent_information instead of the real one.
        MockRepository mocks;
        mocks.ExpectCallFunc(get_subcomponent_information).Return(-1);

        char * result = (char *)load_image_component(NULL, NULL, &size);

        THEN("the function returns NULL") {
            REQUIRE(result == NULL);
        }
        THEN("the size out-argument isn't changed") {
            REQUIRE(size == 0xAA);
        }
    }
}


BinaryFile mock_source_fdt(test_fdt);
static char mock_load_target_fdt_case[1024 * 256];

/**
 * Mock version of the get_subcomponent_information function that enables
 * testing of the FDT loading functions.
 */
int mock_get_subcomponent_information_fdt_case(const void *image, const char *path,
    void **out_load_location, void const**out_data_location, int *out_size,
    int * node_offset) {

    *out_load_location = mock_load_target_fdt_case;
    *out_data_location = mock_source_fdt.raw_bytes();
    *out_size = mock_source_fdt.size();

    return SUCCESS;
}

/**
 * Emulate finding the requested length pointer, so we our test can continue
 * without a valid source image to work with.
 */
const void* mock_fdt_getprop_fdt_case(const void *fdt, int nodeoffset,
    const char *name, int *lenp) {

    // For the target function to continue, this should return a non-zero lenp.
    *lenp = 4;
    return NULL;
}


SCENARIO("using load_image_component to load an FDT", "[load_image_fdt]") {
    WHEN("loading a valid FDT into memory") {
        // Compute the total amount of extra space that can be added to the FDT
        // given the buffer size we have.
        auto extra_space = sizeof(mock_load_target_fdt_case) - mock_source_fdt.size();

        // Ensure that we use our mock get_subcomponent_information instead of the real one.
        MockRepository mocks;
        mocks.ExpectCallFunc(get_subcomponent_information).Do(mock_get_subcomponent_information_fdt_case);
        mocks.ExpectCallFunc(fdt_getprop).Do(mock_fdt_getprop_fdt_case);
        mocks.ExpectCallFunc(__read_extra_space_from_fdt).Return(extra_space);

        char * result = (char *)load_image_fdt(NULL, NULL);

        THEN("the function returns a pointer to image-specified load address") {
            REQUIRE(result == mock_load_target_fdt_case);
        }
        THEN("the target image is a valid FDT") {
            REQUIRE(fdt_check_header(result) == 0);
        }
        THEN("the FDT's new size includes the requested extra space") {
            REQUIRE(fdt_totalsize(result) == (mock_source_fdt.size() + extra_space));
        }
    }
}


SCENARIO("using update_fdt_for_xen to prepare an FDT to launch Xen", "[update_fdt_for_xen]") {
    WHEN("a valid FDT is provided") {
        FlattenedTree fdt(test_fdt);

        // Specify a mock address for our base kernel.
        // This address must fit within 32b, to properly emulate a Xen-compatible
        // load address.
        const void *mock_kernel_address = (void *)0xAABBCCDD;
        const int mock_kernel_size = 1234;

        int rc = update_fdt_for_xen(fdt.raw_bytes(), mock_kernel_address, mock_kernel_size);

        THEN("the function should return success") {
            REQUIRE(rc == SUCCESS);
        }
        THEN("the resultant device tree should contain a kernel section") {
            // Throws an execption if the kernel section doesn't exist.
            fdt.read_property_string("/module@0", "compatible");
        }
        THEN("the resultant kernel section should be marked as a multiboot kernel") {
            bool has_kernel_mark =
              (fdt.read_property_string("/module@0", "compatible") == "multiboot,kernel") ||
              (fdt.read_property_string("/module@0", "compatible", 1) == "multiboot,kernel");
            REQUIRE(has_kernel_mark);
        }
        THEN("the resultant kernel section should be marked as a multiboot module") {
            bool has_module_mark =
              (fdt.read_property_string("/module@0", "compatible") == "multiboot,module") ||
              (fdt.read_property_string("/module@0", "compatible", 1) == "multiboot,module");
            REQUIRE(has_module_mark);
        }
        THEN("the resultant kernel section should contain a correct load address") {
            REQUIRE(fdt.read_property_u64("/module@0", "reg") == 0xAABBCCDD);
        }
        THEN("the resultant kernel section should contain a correct kernel size") {
            REQUIRE(fdt.read_property_u64("/module@0", "reg", 1) == 1234);
        }

    }
}
