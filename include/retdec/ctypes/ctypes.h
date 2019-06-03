/**
* @file include/retdec/ctypes/ctypes.h
* @brief File to include, when all ctypes files are needed.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_CTYPES_H
#define RETDEC_CTYPES_H

#include "retdec/ctypes/annotation.h"
#include "retdec/ctypes/annotation_in.h"
#include "retdec/ctypes/annotation_inout.h"
#include "retdec/ctypes/annotation_optional.h"
#include "retdec/ctypes/annotation_out.h"
#include "retdec/ctypes/array_type.h"
#include "retdec/ctypes/call_convention.h"
#include "retdec/ctypes/composite_type.h"
#include "retdec/ctypes/context.h"
#include "retdec/ctypes/enum_type.h"
#include "retdec/ctypes/exceptions.h"
#include "retdec/ctypes/floating_point_type.h"
#include "retdec/ctypes/function_declaration.h"
#include "retdec/ctypes/function.h"
#include "retdec/ctypes/function_type.h"
#include "retdec/ctypes/header_file.h"
#include "retdec/ctypes/integral_type.h"
#include "retdec/ctypes/member.h"
#include "retdec/ctypes/module.h"
#include "retdec/ctypes/named_type.h"
#include "retdec/ctypes/parameter.h"
#include "retdec/ctypes/pointer_type.h"
#include "retdec/ctypes/reference_type.h"
#include "retdec/ctypes/struct_type.h"
#include "retdec/ctypes/typedefed_type.h"
#include "retdec/ctypes/type.h"
#include "retdec/ctypes/union_type.h"
#include "retdec/ctypes/unknown_type.h"
#include "retdec/ctypes/visitable.h"
#include "retdec/ctypes/visit_all_visitor.h"
#include "retdec/ctypes/visitor.h"
#include "retdec/ctypes/void_type.h"

#endif //RETDEC_CTYPES_H
