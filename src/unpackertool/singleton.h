/**
 * @file src/unpackertool/singleton.h
 * @brief Templated singleton declaration.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef UNPACKERTOOL_SINGLETON_H
#define UNPACKERTOOL_SINGLETON_H

namespace unpackertool {

#define IS_SINGLETON(CLASS)         friend class Singleton<CLASS>;

/**
 * @brief Abstract singleton class.
 *
 * This abstract singleton class can be used for making
 * singletons from any class. You need to put IS_SINGLETON(ClassName)
 * in the class you want to make singleton.
 */
template <typename T> class Singleton
{
public:
	virtual ~Singleton() {}

	/**
	 * Returns the instance of the singleton.
	 *
	 * @return Singleton instance.
	 */
	static T& instance()
	{
		static T instance;
		return instance;
	}

private:
	Singleton();
	Singleton(const Singleton&);
	Singleton& operator =(const Singleton&);
};

} // namespace unpackertool

#endif
