//
// Copyright 2021 Santanu Sen. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution.
//

#ifndef __CRYPTCPP_OPENSSL_ASYMMETRIC_KEY_HPP__
#define __CRYPTCPP_OPENSSL_ASYMMETRIC_KEY_HPP__

#include <cryptcpp/asymmetric_key_crypt.hpp>
#include <openssl/ossl_typ.h>

namespace cryptcpp {
//@{
// @class openssl_asymmetric_key_crypt
// @brief Implements the asymmetric_key_crypt interface with
// openssl asymmetric key encryption routines.
//@}

class openssl_asymmetric_key_crypt : public asymmetric_key_crypt {

public:
  //@{
  // @brief Constructor.
  //
  //@}
  openssl_asymmetric_key_crypt();

  //@{
  // @brief Destructor.
  //@}
  virtual ~openssl_asymmetric_key_crypt();

  //@{
  // @brief Loads asymmetric keys from a file.
  //
  // @param file file containing the input key.
  // @param _key_type input key type.
  // @param password password input key is protected with.
  // @param pass_len password length.
  // @exception throw if invalid keys are passed.
  //@}
  virtual bool set_key(const char *file, key_type _key_type,
                       const char *password, size_t pass_len) override;

  //@{
  // @brief Encrypts data with private key.
  //
  // @param msg_len length of the message to be encrypted.
  // @param msg the message to be encrypted.
  // @param enc_msg output buffer to write the encrypted message.
  // @return length of the encrypted message, negative on error.
  // @exception throw on openssl library call error.
  //@}
  virtual ssize_t private_encrypt(size_t msg_len, const unsigned char *msg,
                                  unsigned char *enc_msg) override;

  //@{
  // @brief Encrypts data with private key.
  //
  // @param msg_len length of the message to be encrypted.
  // @param msg the message to be encrypted.
  // @param enc_msg output buffer to write the encrypted message.
  // @return length of the encrypted message, negative on error.
  // @exception throw on openssl library call error.
  //@}
  virtual ssize_t public_encrypt(size_t msg_len, const unsigned char *msg,
                                 unsigned char *enc_msg) override;

  //@{
  // @brief Decrypts encrypted data using private key.
  //
  // @param enc_msg_len length of the encrypted message.
  // @param enc_msg the message to be decrypted.
  // @param dec_msg output buffer to write the decrypted message.
  // @return length of the decrypted message, negative on error.
  // @exception throw on openssl library call error.
  //@}
  virtual ssize_t private_decrypt(size_t enc_msg_len,
                                  const unsigned char *enc_msg,
                                  unsigned char *dec_msg) override;

  //@{
  // @brief Decrypts encrypted data using public key.
  //
  // @param enc_msg_len length of the encrypted message.
  // @param enc_msg the message to be decrypted.
  // @param dec_msg output buffer to write the decrypted message.
  // @return length of the decrypted message, negative on error.
  // @exception throw on openssl library call error.
  //@}
  virtual ssize_t public_decrypt(size_t enc_msg_len,
                                 const unsigned char *enc_msg,
                                 unsigned char *dec_msg) override;

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
  EVP_PKEY_CTX *common_ctx_init(void);

  //@{
  // The openssl Asymmetric key.
  //@}
  EVP_PKEY *_M_pkey;
};

} // namespace cryptcpp
#endif
