//
// Copyright 2021 Santanu Sen. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution.
//

#ifndef __CRYPTCPP_DIGITAL_SIGNATURE_HPP__
#define __CRYPTCPP_DIGITAL_SIGNATURE_HPP__

#include "asymmetric_key.hpp"
#include "cryptcpp_cpp_std.hpp"
#include "digest.hpp"

namespace cryptcpp {

//@{
// This class specifies an interface for the Digital Signature Algorithm.
//@}

class digital_signature : public asymmetric_key {

public:
  //@{
  // @brief Polymorphic base class.
  //@}
  virtual ~digital_signature() DFLTDSTR;

  //@{
  // @brief Digitally signs a digest with private key.
  //
  // @param digest the digest to be digitally signed.
  // @param digest_len length of the digest.
  // @param sig_buf output buffer where the signature is written.
  // @param sig_buf_len maximum length of the output buffer.
  // @return length of the digital signature.
  //@}
  virtual size_t sign(const unsigned char *digest, size_t digest_len,
                      unsigned char *sig_buf, size_t sig_buf_len) = 0;

  //@{
  // @brief Verifies a digital signature against a digest using a public key.
  //
  // @param digest the digest the signature to verify against.
  // @param digest_len length of the digest.
  // @param signature the digital signature.
  // @param sig_len length of the digital signature.
  // @return true if signature verification passed, else false.
  //@}
  virtual bool verify(const unsigned char *digest, size_t digest_len,
                      const unsigned char *signature, size_t sig_len) = 0;

  //@{
  // @brief Set digest algorithm if valid.
  //
  // @param digest_algo to use in sign or verify.
  // @return true if successful.
  // @exception throw on openssl library call error.
  //@}
  virtual bool set_digest_algo(digest::digest_algorithm digest_algo) = 0;
};

} // namespace cryptcpp
#endif
