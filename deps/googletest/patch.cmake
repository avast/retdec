file(READ "${googletest_path}/googletest/src/gtest-death-test.cc" GTEST_DEATH_TEST)

if(NOT GTEST_DEATH_TEST MATCHES "#[ \t]*include[ \t]*<cstdint>")
	string(REPLACE
		"# include <limits.h>\n"
		"# include <limits.h>\n#include <cstdint>\n"
		GTEST_DEATH_TEST
		"${GTEST_DEATH_TEST}"
	)
	file(WRITE "${googletest_path}/googletest/src/gtest-death-test.cc" "${GTEST_DEATH_TEST}")
endif()
