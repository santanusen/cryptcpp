//
// Copyright 2021 Santanu Sen. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution.
//

#ifndef __CRYPTCPP_CPP_STD_HPP__
#define __CRYPTCPP_CPP_STD_HPP__

#if __cplusplus > 201100L // C++11 or Higher

#define OVERRIDE override
#define DFLTDSTR = default
#define DELETED = delete
#define NOEXCEPT noexcept

#else // C++98 or lower

#include <cstddef>

using std::size_t;
#define nullptr NULL

#define OVERRIDE
#define DFLTDSTR                                                               \
  {}
#define DELETED
#define NOEXCEPT throw()

#endif

#endif
