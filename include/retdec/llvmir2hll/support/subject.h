/**
* @file include/retdec/llvmir2hll/support/subject.h
* @brief Implementation of a generic typed observer (subject part).
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_SUPPORT_SUBJECT_H
#define RETDEC_LLVMIR2HLL_SUPPORT_SUBJECT_H

#include <algorithm>
#include <vector>

#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Implementation of a generic typed observer using shared pointers
*        (subject part).
*
* @tparam SubjectType Type of a subject (usually the class that inherits from
*                     this class).
* @tparam ArgType     Type of an optional argument.
*
* Implements the Observer design pattern.
*
* Usage:
* @code
* class Planet: public Subject<Planet> {
*     private:
*         std::string name;
*     public:
*         Planet(std::string name): Subject<Planet>(this), name(name) {}
*         ~Planet() {}
*         std::string getName() { return name; }
* };
* @endcode
*
* @see Observer
*/
template<typename SubjectType, typename ArgType = SubjectType>
class Subject {
public:
	/// A concrete observer.
	using ConcreteObserver = Observer<SubjectType, ArgType>;

	/// A pointer to an observer.
	// We have to use a weak pointer instead of a shared one because of
	// possible circular references.
	using ObserverPtr = WkPtr<ConcreteObserver>;

public:
	/**
	* @brief Creates a new subject.
	*/
	Subject(): observers() {}

	/**
	* @brief Destructs the subject.
	*/
	virtual ~Subject() {}

	/**
	* @brief Returns a shared pointer of self.
	*
	* Usually, if the class inherits from SharableFromThis<>, then this
	* function can be implemented as
	* @code
	* return shared_from_this();
	* @endcode
	*
	* Notice, however, that then notifyObservers() or removeObserver() cannot
	* be called from a constructor or destructor of the class which inherits
	* from Subject because it is not safe to call shared_from_this() within
	* there.
	*
	* This function is used in notifyObservers() to get the pointer of self.
	* Since shared pointers are used, the situation is a bit more difficult;
	* indeed, one cannot return just @c ShPtr<SubjectType>(this).
	*
	* @see notifyObservers(), removeObserver()
	*/
	virtual ShPtr<SubjectType> getSelf() = 0;

	/**
	* @brief Adds a new observer to the list of observers.
	*
	* @param[in] observer Observer to be added.
	*/
	void addObserver(ObserverPtr observer) {
		observers.push_back(observer);
	}

	/**
	* @brief Removes the selected observer from the list of observers.
	*
	* @param[in] observer Observer to be removed.
	*/
	void removeObserver(ObserverPtr observer) {
		removeObserverAndNonExistingObservers(observer);
	}

	/**
	* @brief Removes all observers.
	*/
	void removeObservers() {
		observers.clear();
	}

	/**
	* @brief Notifies all observers by calling Observer::update() on them.
	*
	* @param[in] arg Optional argument to Observer::update() calls.
	*
	* Observers are notified in the exact order they have been added by
	* addObserver() calls. The function getSelf() is used to get a pointer to
	* the subject.
	*
	* A call to this function may result into the removal of observers that
	* either do not exist or are removed as a consequence of another removal.
	*
	* @see addObserver(), Observer::update(), getSelf()
	*/
	void notifyObservers(ShPtr<ArgType> arg = nullptr) {
		// We have to iterate over a copy of the container because it can be
		// modified during the iteration (either by us or in an update() call).
		for (const auto &observer : ObserverContainer(observers)) {
			notifyObserverOrRemoveItIfNotExists(observer, arg);
		}
	}

protected:
	/// A container to store observers.
	// Note that the used container has to preserve the order in which
	// observers are added to it.
	using ObserverContainer = std::vector<ObserverPtr>;

	// Observer iterator.
	using observer_iterator = typename ObserverContainer::const_iterator;

protected:
	/**
	* @brief Returns a constant iterator to the first observer.
	*/
	observer_iterator observer_begin() const {
		return observers.begin();
	}

	/**
	* @brief Returns a constant iterator past the last observer.
	*/
	observer_iterator observer_end() const {
		return observers.end();
	}

private:

	/**
	* @brief Notifies the given observer (if it exists) or removes it (if it
	*        does not exist).
	*/
	void notifyObserverOrRemoveItIfNotExists(ObserverPtr observer,
			ShPtr<ArgType> arg) {
		if (observerExists(observer)) {
			notifyObserver(observer, arg);
		} else {
			removeObserver(observer);
		}
	}

	/**
	* @brief Checks if the given observer still exists.
	*/
	bool observerExists(ObserverPtr observer) {
		return !observer.expired();
	}

	/**
	* @brief Notifies the given observer, provided it still exists.
	*/
	void notifyObserver(ObserverPtr observer, ShPtr<ArgType> arg) {
		if (ShPtr<ConcreteObserver> existingObserver = observer.lock()) {
			existingObserver->update(getSelf(), arg);
		}
	}

	/**
	* @brief Removes the given observer and all the non-existing observers.
	*/
	void removeObserverAndNonExistingObservers(ObserverPtr observer) {
		observers.erase(std::remove_if(observers.begin(), observers.end(),
			[&observer](const auto &other) {
				return other.expired() || observer.lock() == other.lock();
			}
		));
	}

private:
	/// Container to store observers.
	ObserverContainer observers;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
