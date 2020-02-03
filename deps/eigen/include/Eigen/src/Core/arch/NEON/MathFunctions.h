// This file is part of Eigen, a lightweight C++ template library
// for linear algebra.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef EIGEN_MATH_FUNCTIONS_NEON_H
#define EIGEN_MATH_FUNCTIONS_NEON_H

namespace Eigen {

namespace internal {

template<> EIGEN_DEFINE_FUNCTION_ALLOWING_MULTIPLE_DEFINITIONS EIGEN_UNUSED Packet4f pexp<Packet4f>(const Packet4f& x)
{ return pexp_float(x); }

template<> EIGEN_DEFINE_FUNCTION_ALLOWING_MULTIPLE_DEFINITIONS EIGEN_UNUSED Packet4f plog<Packet4f>(const Packet4f& x)
{ return plog_float(x); }

template<> EIGEN_DEFINE_FUNCTION_ALLOWING_MULTIPLE_DEFINITIONS EIGEN_UNUSED Packet4f psin<Packet4f>(const Packet4f& x)
{ return psin_float(x); }

template<> EIGEN_DEFINE_FUNCTION_ALLOWING_MULTIPLE_DEFINITIONS EIGEN_UNUSED Packet4f pcos<Packet4f>(const Packet4f& x)
{ return pcos_float(x); }

// Hyperbolic Tangent function.
template<> EIGEN_DEFINE_FUNCTION_ALLOWING_MULTIPLE_DEFINITIONS EIGEN_UNUSED Packet4f ptanh<Packet4f>(const Packet4f& x)
{ return internal::generic_fast_tanh_float(x); }

} // end namespace internal

} // end namespace Eigen

#endif // EIGEN_MATH_FUNCTIONS_NEON_H
