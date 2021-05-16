//
// Copyright 2021 Santanu Sen. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution.
//

#ifndef __CRYPTCPP_OPENSSL_DSA_HPP__
#define __CRYPTCPP_OPENSSL_DSA_HPP__

#include <cryptcpp/digital_signature.hpp>
#include <openssl/ossl_typ.h>

namespace cryptcpp {

//@{
// @class openssl_digital_signature
// @brief Implements the digital_signature interface
// using opnssl Digital Signature Algorithm routines.
//@}

class openssl_digital_signature : public digital_signature {

public:
  //@{
  // @brief Constructor.
  //
  //@}
  openssl_digital_signature();

  //@{
  // @brief Destructor.
  //@}
  virtual ~openssl_digital_signature();

  //@{
  // @brief Loads keys from a file.
  //
  // @param file file containing the input key.
  // @param _key_type input key type.
  // @param password password input key is protected with.
  // @param pass_len password length.
  // @exception throw if invalid or non-DSA key is passed.
  //@}
  virtual bool set_key(const char *file, key_type _key_type,
                       const char *password, size_t pass_len) override;

  //@{
  // @brief Digitally signs a digest with DSA private key.
  //
  // @param digest the digest to be digitally signed.
  // @param digest_len length of the digest.
  // @param sign_buf output buffer where the signature is written.
  // @param sign_buf_len maximum length of the output buffer.
  // @return length of the digital signature.
  // @exception throw on openssl library call error.
  //@}
  virtual size_t sign(const unsigned char *digest, size_t digest_len,
                      unsigned char *sign_buf, size_t sign_buf_len) override;

  //@{
  // @brief Verifies a digital signature against a digest
  // using the DSA public key.
  //
  // @param digest the digest the signature to verify against.
  // @param digest_len length of the digest.
  // @param signature the digital signature.
  // @param sign_len length of the digital signature.
  // @return true if signature verification passed, else false.
  // @exception throw on openssl library call error.
  //@}
  virtual bool verify(const unsigned char *digest, size_t digest_len,
                      const unsigned char *signature, size_t sign_len) override;

  //@{
  // @brief Set digest algorithm if valid.
  //
  // @param digest_algo to use in sign or verify.
  // @return true if successful.
  // @exception throw on openssl library call error.
  //@}
  virtual bool set_digest_algo(digest::digest_algorithm digest_algo) override;

private:
  //@{
  // @brief Update _M_Key to pkey if valid.
  //
  // @param pkey key to update to.
  // @return true if successful.
  // @exception throw on openssl library call error.
  //@}
  bool update_key(EVP_PKEY *pkey);

  //@{
  // @brief Common context initializer.
  //
  // @return pointer to new context.
  // @exception throw on openssl library call error.
  //@}
  EVP_MD_CTX *common_ctx_init(void);

  //@{
  // The digest algorithm.
  //@}
  const EVP_MD *_M_md;

  //@{
  // The openssl DSA key.
  //@}
  EVP_PKEY *_M_key;
};

} // namespace cryptcpp
#endif
