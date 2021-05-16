//
// Copyright 2021 Santanu Sen. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution.
//

#ifndef __CRYPTCPP_OPENSSL_EXCEPTION_HPP__
#define __CRYPTCPP_OPENSSL_EXCEPTION_HPP__

#include <cryptcpp/crypt_exception.hpp>

namespace cryptcpp {

//@{
// @class openssl_exception
// @brief Extends crypt_exception by appending openssl library errors to
// error message string.
//@}

class openssl_exception : public crypt_exception {

public:
  //@{
  // @brief Constructor. Initializes error message string with msg and
  // appends openssl library error messages to it.
  // @param msg the string to initialize error message.
  //@}
  explicit openssl_exception(const std::string &msg);
};

} // namespace cryptcpp
#endif
