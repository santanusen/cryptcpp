//
// Copyright 2021 Santanu Sen. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution.
//

#include <cryptcpp/cryptcpp_util.hpp>
#include <cryptcpp/impl/openssl/openssl_digest.hpp>
#include <cryptcpp/impl/openssl/openssl_exception.hpp>

#include <openssl/evp.h>

//#include <cstring>
//#include <string>

namespace cryptcpp {

openssl_digest::openssl_digest() : _M_md(nullptr) {}

size_t openssl_digest::calculate_digest(const unsigned char *data,
                                        size_t data_len,
                                        unsigned char *digest_buf,
                                        size_t digest_buf_len) {
  if (!_M_md) {
    report_exception(openssl_exception("openssl_digest: Digest algo not set"));
    return 0;
  }

  cryptcpp_unique_ptr<EVP_MD_CTX> mdctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (!mdctx) {
    report_exception(openssl_exception("EVP_MD_CTX_new:"));
    return 0;
  }

  if (1 != EVP_DigestInit(mdctx.get(), _M_md)) {
    report_exception(openssl_exception("EVP_DigestInit:"));
    return 0;
  }

  if (1 != EVP_DigestUpdate(mdctx.get(), data, data_len)) {
    report_exception(openssl_exception("EVP_DigestUpdate:"));
    return 0;
  }

  unsigned int digest_len = digest_buf_len;
  if (1 != EVP_DigestFinal(mdctx.get(), digest_buf, &digest_len)) {
    report_exception(openssl_exception("EVP_DigestFinal:"));
    return 0;
  }

  return digest_len;
}

bool openssl_digest::set_digest_algorithm(digest_algorithm digest_algo) {
  // Get the EVP_MD object associated with the digest algorithm.
  const EVP_MD *eMd = EVP_get_digestbyname(digest_algo);
  if (!eMd) {
    report_exception(openssl_exception("Unsupported Digest Algorithm:"));
    return false;
  }

  _M_md = eMd;
  return true;
}

} // namespace cryptcpp
