//
// Copyright 2021 Santanu Sen. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution.
//

#ifndef __CRYPTCPP_OPENSSL_SYMMETRIC_KEY_CRYPT_HPP__
#define __CRYPTCPP_OPENSSL_SYMMETRIC_KEY_CRYPT_HPP__

#include <cryptcpp/symmetric_key_crypt.hpp>
#include <openssl/ossl_typ.h>

namespace cryptcpp {

#define CIPHER_BLOCK_SIZE 128

//@{
// @class openssl_symmetric_key_crypt
//
// Implemnts the cryptcpp:: symmetric_key_crypt interface for symmetric
// key cryptographic algorithms using openssl APIs.
//@}

class openssl_symmetric_key_crypt : public symmetric_key_crypt {

public:
  //@{
  // Constructor.
  //@}
  openssl_symmetric_key_crypt();

  //@{
  // @brief Sets the key for encryption/decryption.
  //
  // @param key raw symmetric key.
  // @param key_len length of the key.
  //@}
  virtual void set_key(const unsigned char *key, size_t keyLen) override;

  //@{
  // @brief Sets the cipher algorithm.
  //
  // @param _cipher_type symmetric key algorithm type.
  // @param _cipher_mode symmetric key algorithm mode.
  // @return true if successful.
  //@}
  virtual bool set_cipher(cipher_type _cipher_type,
                          cipher_mode _cipher_mode) override;

  //@{
  // @brief Sets padding on or off.
  //
  // @param pad switch on or off.
  //@}
  virtual void set_padding(bool pad) override { _M_padding = pad; }

  //@{
  // @brief Decrypts an encrypted message with symmetric key using the
  // associated algorithm and mode.
  //
  // @param in_buf input buffer containing the encrypted message.
  // @param plain_buf output buffer to write the decrypted data.
  // @param in_len length of the encrypted message.
  // @param max_out_len size of the output buffer.
  // @return decrypted message length.
  //@}
  virtual size_t decrypt(const unsigned char *in_buf, unsigned char *plain_buf,
                         size_t in_len, size_t max_out_len) override;

  //@{
  // @brief Encrypts a message with symmetric key using the
  // associated algorithm and mode.
  //
  // @param in_buf input buffer containing the message to encrypt.
  // @param cipher_buf output buffer to write the encrypted data.
  // @param in_len length of the input message.
  // @param max_out_len size of the output buffer.
  // @param iv initialization vector.
  // @return encrypted message length.
  //@}
  virtual size_t encrypt(const unsigned char *in_buf, unsigned char *cipher_buf,
                         size_t in_len, size_t max_out_len,
                         const unsigned char *iv) override;

private:
  //@{
  // @brief The openssl cipher.
  //@}
  const EVP_CIPHER *_M_evp_cipher;

  //@{
  // @brief Buffer to hold the raw symmetric encryption/decryption key.
  //@}
  unsigned char _M_key_buf[MAX_SYMMETRIC_KEY_LENGTH];

  //@{
  // @brief Key length.
  //@}
  size_t _M_key_length;

  //@{
  // @brief if padding is needed
  //@}
  bool _M_padding;
};

} // namespace cryptcpp
#endif
