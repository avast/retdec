
#ifndef RETDEC_DEM_TEST_H
#define RETDEC_DEM_TEST_H

#define DEM_EQ(mangled, demangled) \
            do {    \
                EXPECT_EQ(demangler->demangleToString(mangled), demangled); \
                EXPECT_EQ(demangler->status(), status::success); \
            } while(0)

#define DEM_FAIL(mangled, expected_status) \
			do { \
				EXPECT_EQ(demangler->demangleToString(mangled), ""); \
				EXPECT_EQ(demangler->status(), expected_status); \
			} while(0)

#endif //RETDEC_DEM_TEST_H
