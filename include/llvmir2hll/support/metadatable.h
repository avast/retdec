/**
* @file include/llvmir2hll/support/metadatable.h
* @brief A mixin providing metadata attached to objects.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef LLVMIR2HLL_SUPPORT_METADATABLE_H
#define LLVMIR2HLL_SUPPORT_METADATABLE_H

namespace llvmir2hll {

/**
* @brief A mixin providing metadata attached to objects.
*
* @tparam T Type of metadata.
*/
template<typename T>
class Metadatable {
public:
	/**
	* @brief Destructs the object.
	*/
	~Metadatable() {}

	/**
	* @brief Attaches new metadata.
	*
	* @param[in] data Metadata to be attached.
	*/
	void setMetadata(T data) {
		this->data = data;
	}

	/**
	* @brief Returns the attached metadata.
	*/
	T getMetadata() const {
		return data;
	}

	/**
	* @brief Are there any non-empty metadata?
	*/
	bool hasMetadata() const {
		return !data.empty();
	}

protected:
	/**
	* @brief Constructs a new metadatable object.
	*/
	Metadatable(): data() {}

private:
	/// Attached metadata.
	T data;
};

} // namespace llvmir2hll

#endif
