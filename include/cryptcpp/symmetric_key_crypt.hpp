//
// Copyright 2021 Santanu Sen. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution.
//

#ifndef __CRYPTCPP_SYMMETRIC_KEY_CRYPT_HPP__
#define __CRYPTCPP_SYMMETRIC_KEY_CRYPT_HPP__

#include <string>

namespace cryptcpp {

constexpr size_t MAX_SYMMETRIC_KEY_LENGTH = 64; // 512 bits

//@{
// @class symmetric_key_crypt
//
// @brief Interface for symmetric key crypt algorithms.
//@}

class symmetric_key_crypt {

public:
  //@{
  // @brief Types of symmetric key algorithms.
  //@}
  typedef const char *cipher_type;
  static inline cipher_type CIPHER_AES_128() { return "aes-128"; }
  static inline cipher_type CIPHER_AES_192() { return "aes-192"; }
  static inline cipher_type CIPHER_AES_256() { return "aes-256"; }
  static inline cipher_type CIPHER_BF() { return "bf"; }
  static inline cipher_type CIPHER_CAMELLIA() { return "camellia"; }
  static inline cipher_type CIPHER_CAST() { return "cast"; }
  static inline cipher_type CIPHER_CAST5() { return "cast5"; }
  static inline cipher_type CIPHER_DES() { return "des"; }
  static inline cipher_type CIPHER_DES_EDE() { return "des-ede"; }
  static inline cipher_type CIPHER_DES_EDE3() { return "des-ede3"; }
  static inline cipher_type CIPHER_DES3() { return "des3"; }
  static inline cipher_type CIPHER_DESX() { return "desx"; }
  static inline cipher_type CIPHER_RC2() { return "rc2"; }
  static inline cipher_type CIPHER_RC2_40() { return "rc42-40"; }
  static inline cipher_type CIPHER_RC2_64() { return "rc2-64"; }
  static inline cipher_type CIPHER_RC4() { return "rc4"; }
  static inline cipher_type CIPHER_RC4_40() { return "rc4-40"; }
  static inline cipher_type CIPHER_SEED() { return "seed"; }

  //@{
  // @brief Modes in which the symmetric key algorithms work.
  //@}
  typedef const char *cipher_mode;
  static inline cipher_mode CIPHER_MODE_NONE() { return ""; }
  static inline cipher_mode CIPHER_MODE_ECB() { return "ecb"; }
  static inline cipher_mode CIPHER_MODE_CBC() { return "cbc"; }
  static inline cipher_mode CIPHER_MODE_CFB() { return "cfb"; }
  static inline cipher_mode CIPHER_MODE_OFB() { return "ofb"; }
  static inline cipher_mode CIPHER_MODE_CTR() { return "ctr"; }
  static inline cipher_mode CIPHER_MODE_GCM() { return "gcm"; }
  static inline cipher_mode CIPHER_MODE_XTS() { return "xts"; }

  //@{
  // @brief Polymorphic base class.
  //@}
  virtual ~symmetric_key_crypt() = default;

  //@{
  // @brief Sets the key for encryption/decryption.
  //
  // @param key raw symmetric key.
  // @param key_len length of the key.
  //@}
  virtual void set_key(const unsigned char *key, size_t key_len) = 0;

  //@{
  // @brief Sets the cipher algorithm.
  //
  // @param _cipher_type symmetric key algorithm type.
  // @param _cipher_mode symmetric key algorithm mode.
  // @return true if successful.
  //@}
  virtual bool set_cipher(cipher_type _cipher_type,
                          cipher_mode _cipher_mode) = 0;

  //@{
  // @brief Sets padding on or off.
  //
  // @param pad switch on or off.
  //@}
  virtual void set_padding(bool pad) = 0;

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
                         size_t in_len, size_t max_out_len) = 0;

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
                         const unsigned char *iv = nullptr) = 0;
};

} // namespace cryptcpp
#endif
