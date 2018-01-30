/**
* @file tests/utils/time_tests.cpp
* @brief Tests for the @c time module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <cstdlib>
#include <ctime>
#include <string>

#include <gtest/gtest.h>

#include "retdec/utils/os.h"
#include "retdec/utils/time.h"

using namespace ::testing;

namespace retdec {
namespace utils {
namespace tests {

/**
* @brief Tests for the @c time module.
*/
class TimeTests: public Test {
protected:
	virtual void SetUp() override {
		// We have to force a specific timezone to make the tests
		// deterministic (#90).
		changeTimezoneToUTC();
	}

	virtual void TearDown() override {
		changeTimezoneBackToOriginalValue();
	}

	void changeTimezoneToUTC() {
		// Store the original timezone so we can set it back in
		// changeTimezoneBackToOriginalValue().
		// Both Windows and POSIX use the same variable.
		const auto TZ = std::getenv("TZ");
		if (TZ) {
			originalTZ = TZ;
		}

		#ifdef OS_WINDOWS
			_putenv("TZ=UTC");
			_tzset();
		#else
			setenv("TZ", "UTC", /*overwrite=*/1);
			tzset();
		#endif
	}

	void changeTimezoneBackToOriginalValue() {
		#ifdef OS_WINDOWS
			// Calling _putenv() specifying "VAR=" as a parameter (i.e. without
			// the value) deletes the environment variable, which is what we
			// want if originalTZ is empty.
			const auto TZ_ENV = "TZ=" + originalTZ;
			_putenv(TZ_ENV.c_str());
			_tzset();
		#else
			if (originalTZ.empty()) {
				unsetenv("TZ");
			} else {
				setenv("TZ", originalTZ.c_str(), /*overwrite=*/1);
			}
			tzset();
		#endif
	}

private:
	// Originally set timezone.
	std::string originalTZ;
};

//
// timestampToDate()
//

TEST_F(TimeTests,
CorrectTimestampToDateConversion) {
	EXPECT_EQ("2015-08-05 14:25:19", timestampToDate(std::time_t(1438784719)));
}

} // namespace tests
} // namespace utils
} // namespace retdec
