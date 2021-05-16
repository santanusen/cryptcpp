//
// Copyright 2021 Santanu Sen. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution.
//

#include <cryptcpp/impl/openssl/openssl_exception.hpp>
#include <openssl/err.h>

namespace cryptcpp {

openssl_exception::openssl_exception(const std::string &msg)
    : crypt_exception(msg) {
  char buf[256];
  unsigned long err;

  // Append openssl library error messages.
  while ((err = ERR_get_error()) != 0) {
    ERR_error_string_n(err, buf, sizeof(buf));
    _M_err_msg += (std::string("\n") + buf);
  }
}

} // namespace cryptcpp
