//
// Copyright 2021 Santanu Sen. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution.
//

#ifndef __CRYPTCPP_ASYMMETRIC_KEY_CRYPT_HPP__
#define __CRYPTCPP_ASYMMETRIC_KEY_CRYPT_HPP__

#include "asymmetric_key.hpp"
#include "cryptcpp_cpp_std.hpp"

namespace cryptcpp {

//@{
// @class casymmetric_key
// @brief Interface for asymmetric key encryption.
//@}

class asymmetric_key_crypt : public asymmetric_key {

public:
  //@{
  // @brief Polymorphic base class.
  //@}
  virtual ~asymmetric_key_crypt() DFLTDSTR;

  //@{
  // @brief Encrypts data with private key.
  //
  // @param msg_len length of the message to be encrypted.
  // @param msg the message to be encrypted.
  // @param enc_msg output buffer to write the encrypted message.
  // @return length of the encrypted message, negative on error.
  //@}
  virtual ssize_t private_encrypt(size_t msg_len, const unsigned char *msg,
                                  unsigned char *enc_msg) = 0;

  //@{
  // @brief Encrypts data with public key.
  //
  // @param msg_len length of the message to be encrypted.
  // @param msg the message to be encrypted.
  // @param enc_msg output buffer to write the encrypted message.
  // @return length of the encrypted message, negative on error.
  //@}
  virtual ssize_t public_encrypt(size_t msg_len, const unsigned char *msg,
                                 unsigned char *enc_msg) = 0;

  //@{
  // @brief Decrypts encrypted data using private key.
  //
  // @param enc_msg_len length of the encrypted message.
  // @param enc_msg the message to be decrypted.
  // @param dec_msg output buffer to write the decrypted message.
  // @return length of the decrypted message, negative on error.
  //@}
  virtual ssize_t private_decrypt(size_t enc_msg_len,
                                  const unsigned char *enc_msg,
                                  unsigned char *dec_msg) = 0;

  //@{
  // @brief Decrypts encrypted data using public key.
  //
  // @param enc_msg_len length of the encrypted message.
  // @param enc_msg the message to be decrypted.
  // @param dec_msg output buffer to write the decrypted message.
  // @return length of the decrypted message, negative on error.
  //@}
  virtual ssize_t public_decrypt(size_t enc_msg_len,
                                 const unsigned char *enc_msg,
                                 unsigned char *dec_msg) = 0;
};

} // namespace cryptcpp
#endif
