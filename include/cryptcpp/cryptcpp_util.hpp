//
// Copyright 2021 Santanu Sen. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution.
//

#ifndef __CRYPTCPP_UTIL_HPP__
#define __CRYPTCPP_UTIL_HPP__

#include <functional>
#include <memory>

namespace cryptcpp {

template <typename T>
using cryptcpp_unique_ptr = std::unique_ptr<T, std::function<void(T *)>>;

} // namespace cryptcpp
#endif
