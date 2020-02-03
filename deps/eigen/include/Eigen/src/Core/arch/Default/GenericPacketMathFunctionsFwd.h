// This file is part of Eigen, a lightweight C++ template library
// for linear algebra.
//
// Copyright (C) 2019 Gael Guennebaud <gael.guennebaud@inria.fr>
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef EIGEN_ARCH_GENERIC_PACKET_MATH_FUNCTIONS_FWD_H
#define EIGEN_ARCH_GENERIC_PACKET_MATH_FUNCTIONS_FWD_H

namespace Eigen {
namespace internal {

// Forward declarations of the generic math functions
// implemented in GenericPacketMathFunctions.h
// This is needed to workaround a circular dependency.

template<typename Packet> EIGEN_STRONG_INLINE Packet
pfrexp_float(const Packet& a, Packet& exponent);

template<typename Packet> EIGEN_STRONG_INLINE Packet
pldexp_float(Packet a, Packet exponent);

/** \internal \returns log(x) for single precision float */
template <typename Packet>
EIGEN_DEFINE_FUNCTION_ALLOWING_MULTIPLE_DEFINITIONS
EIGEN_UNUSED
Packet plog_float(const Packet _x);

/** \internal \returns log(1 + x) */
template<typename Packet>
Packet generic_plog1p(const Packet& x);

/** \internal \returns exp(x)-1 */
template<typename Packet>
Packet generic_expm1(const Packet& x);

/** \internal \returns exp(x) for single precision float */
template <typename Packet>
EIGEN_DEFINE_FUNCTION_ALLOWING_MULTIPLE_DEFINITIONS
EIGEN_UNUSED
Packet pexp_float(const Packet _x);

/** \internal \returns exp(x) for double precision real numbers */
template <typename Packet>
EIGEN_DEFINE_FUNCTION_ALLOWING_MULTIPLE_DEFINITIONS
EIGEN_UNUSED
Packet pexp_double(const Packet _x);

/** \internal \returns sin(x) for single precision float */
template<typename Packet>
EIGEN_DEFINE_FUNCTION_ALLOWING_MULTIPLE_DEFINITIONS
EIGEN_UNUSED
Packet psin_float(const Packet& x);

/** \internal \returns cos(x) for single precision float */
template<typename Packet>
EIGEN_DEFINE_FUNCTION_ALLOWING_MULTIPLE_DEFINITIONS
EIGEN_UNUSED
Packet pcos_float(const Packet& x);

template <typename Packet, int N> struct ppolevl;

} // end namespace internal
} // end namespace Eigen

#endif // EIGEN_ARCH_GENERIC_PACKET_MATH_FUNCTIONS_FWD_H
