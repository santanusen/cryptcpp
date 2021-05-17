//
// Copyright 2021 Santanu Sen. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution.
//

#ifndef __CRYPTCPP_ASYMMETRIC_KEY_HPP__
#define __CRYPTCPP_ASYMMETRIC_KEY_HPP__

#include "cryptcpp_cpp_std.hpp"
#include <cstdlib>

namespace cryptcpp {

//@{
// @class asymmetric_key
// @brief Interface for asymmetric key crypt algorithms.
//@}

class asymmetric_key {

public:
  //@{
  // Types of Asymmetric Keys.
  //@}
  enum key_type { ASYM_KEY_KEY, ASYM_KEY_PUBLIC, ASYM_KEY_PRIVATE };

  //@{
  // @brief Loads asymmetric keys from a uri.
  //
  // @param uri uri containing the input key.
  // @param keyType input key type.
  // @param password password input key is protected with.
  // @param passLen password length.
  //@}
  virtual bool set_key(const char *key_file, key_type _key_type,
                       const char *password = nullptr, size_t pass_len = 0) = 0;
};

} // namespace cryptcpp
#endif
