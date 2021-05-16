//
// Copyright 2021 Santanu Sen. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution.
//

#include <cryptcpp/cryptcpp_util.hpp>
#include <cryptcpp/impl/openssl/openssl_exception.hpp>
#include <cryptcpp/impl/openssl/openssl_symmetric_key_crypt.hpp>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <cstring>

namespace cryptcpp {

openssl_symmetric_key_crypt::openssl_symmetric_key_crypt()
    : _M_evp_cipher(nullptr), _M_key_length(0), _M_padding(true) {}

void openssl_symmetric_key_crypt::set_key(const unsigned char *key,
                                          size_t key_len) {
  memset(_M_key_buf, 0, MAX_SYMMETRIC_KEY_LENGTH);

  if (key) {
    memcpy(_M_key_buf, key, key_len);
    _M_key_length = key_len;
  } else {
    _M_key_length = 0;
  }
}

bool openssl_symmetric_key_crypt::set_cipher(cipher_type _cipher_type,
                                             cipher_mode _cipher_mode) {
  // Get the cipher name prefix.
  std::string cipher_name = _cipher_type;
  // Append the cipher mode.
  const std::string ciph_mode = _cipher_mode;
  if (!ciph_mode.empty()) {
    cipher_name = cipher_name + std::string("-") + ciph_mode;
  }
  // Get the cipher envelope by name.
  const EVP_CIPHER *evp_cipher = EVP_get_cipherbyname(cipher_name.c_str());
  if (!evp_cipher) {
    report_exception(openssl_exception("Unsupported Cipher"));
    return false;
  }

  _M_evp_cipher = evp_cipher;
  return true;
}

size_t openssl_symmetric_key_crypt::decrypt(const unsigned char *in_buf,
                                            unsigned char *plain_buf,
                                            size_t in_len, size_t max_out_len) {
  // decrypt_init
  if (_M_key_length == 0) {
    report_exception(openssl_exception("decrypt: Key not set"));
    return 0;
  }

  if (!_M_evp_cipher) {
    report_exception(openssl_exception("Cipher algorithm not set"));
    return 0;
  }

  int iv_length = EVP_CIPHER_iv_length(_M_evp_cipher);
  const unsigned char *iv = nullptr;
  if (iv_length > 0) {
    iv = in_buf;
  } else {
    iv_length = 0;
  }

  // In GCM mode first 16 bytes is tag followed by IV
  const size_t tag_length =
      (EVP_CIPHER_mode(_M_evp_cipher) == EVP_CIPH_GCM_MODE) ? 16 : 0;

  size_t offset = iv_length + tag_length;

  // IV length for the algorithm cannot be more than input size.
  if (offset > in_len) {
    report_exception(openssl_exception("Not enough data passed in to get IV"));
    return 0;
  }

  cryptcpp_unique_ptr<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new(),
                                          EVP_CIPHER_CTX_free);
  if (!ctx) {
    report_exception(openssl_exception("EVP_CIPHER_CTX_new:"));
    return 0;
  }
  EVP_CIPHER_CTX_init(ctx.get());

  // Initialize context with cipher, key and IV.
  if (1 != EVP_DecryptInit_ex(ctx.get(), _M_evp_cipher, nullptr, _M_key_buf,
                              &iv[tag_length])) {
    report_exception(openssl_exception("Not enough data passed in to get IV"));
    return 0;
  }

  if (in_len - offset > max_out_len) {
    report_exception(openssl_exception("Not enough space in output buffer"));
    return 0;
  }

  int outl = max_out_len;
  // Perform decryption.
  if (EVP_DecryptUpdate(ctx.get(), plain_buf, &outl, in_buf + offset,
                        in_len - offset) == 0) {
    report_exception(openssl_exception("EVP_DecryptUpdate"));
    return 0;
  }

  if (tag_length > 0) {
    if (EVP_CIPHER_CTX_ctrl(
            ctx.get(), EVP_CTRL_GCM_SET_TAG, tag_length,
            static_cast<void *>(const_cast<unsigned char *>(in_buf))) == 0) {
      report_exception(openssl_exception("EVP_CIPHER_CTX_ctrl:"));
      return 0;
    }
  }

  size_t plain_data_len = outl;

  // Decrypt partial blocks, if any.
  if (EVP_DecryptFinal(ctx.get(), plain_buf, &outl) == 0) {
    report_exception(openssl_exception("EVP_DecryptFinal:"));
    return 0;
  }

  plain_data_len += outl;

  if (plain_data_len > max_out_len) {
    report_exception(openssl_exception("Plaintext output > max_out_len"));
    return 0;
  }

  EVP_CIPHER_CTX_cleanup(ctx.get());
  return plain_data_len;
}

size_t openssl_symmetric_key_crypt::encrypt(const unsigned char *in_buf,
                                            unsigned char *cipher_buf,
                                            size_t in_len, size_t max_out_len,
                                            const unsigned char *iv) {
  // encrypt_init
  if (_M_key_length == 0) {
    report_exception(openssl_exception("encrypt: Key not set"));
    return 0;
  }

  if (!_M_evp_cipher) {
    report_exception(openssl_exception("Cipher algorithm not set"));
    return 0;
  }

  int iv_length = EVP_CIPHER_iv_length(_M_evp_cipher);
  // In GCM mode first 16 bytes is tag followed by IV
  const size_t tag_length =
      (EVP_CIPHER_mode(_M_evp_cipher) == EVP_CIPH_GCM_MODE) ? 16 : 0;

  if (iv_length > 0) {
    if (iv_length + tag_length > max_out_len) {
      report_exception(
          openssl_exception("Not enough space in output buffer for IV"));
      return 0;
    }

    if (iv == nullptr) {
      // IV needed but not specified. Generate.
      if ((RAND_status() != 1) ||
          (RAND_bytes(&cipher_buf[tag_length], iv_length) != 1)) {
        report_exception(openssl_exception("Generating random iv failed"));
        return 0;
      }
      iv = &cipher_buf[tag_length];
    } else {
      // The first block of encrypted data contains the IV.
      memcpy(&cipher_buf[tag_length], iv, iv_length);
    }
  } else {
    iv_length = 0;
  }

  cryptcpp_unique_ptr<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new(),
                                          EVP_CIPHER_CTX_free);
  if (!ctx) {
    report_exception(openssl_exception("EVP_CIPHER_CTX_new:"));
    return 0;
  }
  EVP_CIPHER_CTX_init(ctx.get());

  // Initialize context with cipher, key and IV.
  if (1 !=
      EVP_EncryptInit_ex(ctx.get(), _M_evp_cipher, nullptr, _M_key_buf, iv)) {
    report_exception(openssl_exception("EVP_EncryptInit_ex"));
    return 0;
  }

  // disble padding if configured
  if (_M_padding == false) {
    EVP_CIPHER_CTX_set_padding(ctx.get(), 0);
  }

  size_t offset = iv_length + tag_length;

  // encrypt_update
  if (in_len + offset > max_out_len) {
    report_exception(openssl_exception("encrypt: Insufficient output buffer"));
    return 0;
  }

  int outl = max_out_len - offset;
  // Perform encryption.
  if (1 != EVP_EncryptUpdate(ctx.get(), &cipher_buf[offset], &outl, in_buf,
                             in_len)) {
    report_exception(openssl_exception("EVP_EncryptUpdate"));
    return 0;
  }

  size_t cipher_data_len = offset + outl;

  outl = max_out_len - cipher_data_len;
  // Finish up with padding if needed.
  if (EVP_EncryptFinal(ctx.get(), cipher_buf, &outl) == 0) {
    report_exception(openssl_exception("EVP_EncryptFinal:"));
    return 0;
  }

  cipher_data_len += outl;

  if (cipher_data_len > max_out_len) {
    report_exception(openssl_exception("Cipher output > max_out_len"));
    return 0;
  }

  if (tag_length > 0) {
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, tag_length,
                            cipher_buf) == 0) {
      report_exception(openssl_exception("EVP_CIPHER_CTX_ctrl:"));
      return 0;
    }
  }

  EVP_CIPHER_CTX_cleanup(ctx.get());
  return cipher_data_len;
}

} // namespace cryptcpp
