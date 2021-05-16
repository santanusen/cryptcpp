//
// Copyright 2021 Santanu Sen. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution.
//

#ifndef __CRYPTCPP_OPENSSL_KEY_UTIL_HPP__
#define __CRYPTCPP_OPENSSL_KEY_UTIL_HPP__

#include <cryptcpp/asymmetric_key.hpp>
#include <openssl/ossl_typ.h>

namespace cryptcpp {

//@{
// @namespace openssl_key_util
// @brief Provides utility functions to read openssl keys.
//@}
//

namespace openssl_key_util {

//@{
// @brief Reads openssl keys from a uri and returns
// a pointer to the corresponding EVP_PKEY structure.
//
// @param file file containing the input key.
// @param _key_type input key type.
// @param password password input key is protected with.
// @param pass_len password length.
// @return pointer to EVP_PKEY corresponding to the input key.
// @exception throw if invalid file is passed.
//@}
EVP_PKEY *read_key(const char *uri, asymmetric_key::key_type _key_type,
                   const char *password, size_t pass_len);

} // namespace openssl_key_util

} // namespace cryptcpp
#endif
