//
// Copyright 2021 Santanu Sen. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution.
//

#ifndef __CRYPTCPP_OPENSSL_DIGEST_HPP__
#define __CRYPTCPP_OPENSSL_DIGEST_HPP__

#include <cryptcpp/digest.hpp>
#include <openssl/ossl_typ.h>

namespace cryptcpp {

//@{
// @class openssl_digest
// @brief Implements the digest interface for digest/hash
// calculation using openssl routines.
//@}

class openssl_digest : public digest {

public:
  //@{
  // @brief Constructor.
  //
  // @param digest_algo the digest calculation algorithm to use.
  //@}
  explicit openssl_digest();

  //@{
  // @brief calculates the digest of the given data.
  //
  // @param data input data whose digest is to be calculated.
  // @param data_len length of input data.
  // @param digest_buf output buffer to write calculated digest.
  // @param digest_buf_len maximum size of the output buffer.
  // @return length of the digest.
  //@}
  virtual size_t calculate_digest(const unsigned char *data, size_t data_len,
                                  unsigned char *digest_buf,
                                  size_t digest_buf_len) OVERRIDE;

  //@{
  // @brief Sets the digest calculation algorithm to use.
  // @param _digest_algorithm the digest calculation algorithm to use.
  // @return true if successful.
  // @throw on ssl library call error.
  //@}
  virtual bool set_digest_algorithm(digest_algorithm digest_algo) OVERRIDE;

private:
  //@{
  // @brief The OpenSSL message digest structure.
  //@}
  const EVP_MD *_M_md;
};

} // namespace cryptcpp
#endif
