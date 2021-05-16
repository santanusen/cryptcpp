//
// Copyright 2021 Santanu Sen. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution.
//

#include <cryptcpp/cryptcpp_util.hpp>
#include <cryptcpp/impl/openssl/openssl_asymmetric_key_crypt.hpp>
#include <cryptcpp/impl/openssl/openssl_exception.hpp>
#include <cryptcpp/impl/openssl/openssl_key_util.hpp>

#include <openssl/evp.h>

namespace cryptcpp {

openssl_asymmetric_key_crypt::openssl_asymmetric_key_crypt()
    : _M_pkey(nullptr) {}

openssl_asymmetric_key_crypt::~openssl_asymmetric_key_crypt() {
  if (_M_pkey)
    EVP_PKEY_free(_M_pkey);
}

bool openssl_asymmetric_key_crypt::update_key(EVP_PKEY *pkey) {
  if (!pkey) {
    report_exception(openssl_exception("Could not read key:"));
    return false;
  }

  if (_M_pkey) {
    EVP_PKEY_free(_M_pkey);
  }
  _M_pkey = pkey;

  return true;
}

bool openssl_asymmetric_key_crypt::set_key(const char *file, key_type _key_type,
                                           const char *password,
                                           size_t pass_len) {
  // Get the key envelope structure for the key file.
  EVP_PKEY *pkey =
      openssl_key_util::read_key(file, _key_type, password, pass_len);
  return update_key(pkey);
}

EVP_PKEY_CTX *openssl_asymmetric_key_crypt::common_ctx_init() {
  if (!_M_pkey) {
    report_exception(
        openssl_exception("openssl_asymmetric_key_crypt: Key not set"));
    return nullptr;
  }

  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(_M_pkey, nullptr);
  // EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, _M_pkey, nullptr);
  if (!ctx) {
    report_exception(openssl_exception("EVP_PKEY_CTX_new:"));
    return nullptr;
  }
  return ctx;
}

ssize_t openssl_asymmetric_key_crypt::private_encrypt(size_t msg_len,
                                                      const unsigned char *msg,
                                                      unsigned char *enc_msg) {
  cryptcpp_unique_ptr<EVP_PKEY_CTX> ctx(common_ctx_init(), EVP_PKEY_CTX_free);
  if (!ctx) {
    return -1;
  }

  if (EVP_PKEY_sign_init(ctx.get()) <= 0) {
    report_exception(openssl_exception("EVP_PKEY_CTX_sign_init:"));
    return -1;
  }

  size_t outlen;
  if (EVP_PKEY_sign(ctx.get(), enc_msg, &outlen, msg, msg_len) <=
      0) { // TODO: get length with outbuf = null
    report_exception(openssl_exception("EVP_PKEY_CTX_sign:"));
    return -1;
  }

  return static_cast<ssize_t>(outlen); // TODO: size_t
}

ssize_t openssl_asymmetric_key_crypt::public_decrypt(
    size_t enc_msg_len, const unsigned char *enc_msg, unsigned char *dec_msg) {
  cryptcpp_unique_ptr<EVP_PKEY_CTX> ctx(common_ctx_init(), EVP_PKEY_CTX_free);
  if (!ctx) {
    return -1;
  }

  if (EVP_PKEY_verify_recover_init(ctx.get()) <= 0) {
    report_exception(openssl_exception("EVP_PKEY_verify_recover_init:"));
    return -1;
  }

  size_t outlen;
  if (EVP_PKEY_verify_recover(ctx.get(), dec_msg, &outlen, enc_msg,
                              enc_msg_len) <=
      0) { // TODO: get length with outbuf = null
    report_exception(openssl_exception("EVP_PKEY_CTX_verify_recover:"));
    return -1;
  }

  return static_cast<ssize_t>(outlen); // TODO: size_t
}

ssize_t openssl_asymmetric_key_crypt::public_encrypt(size_t msg_len,
                                                     const unsigned char *msg,
                                                     unsigned char *enc_msg) {
  cryptcpp_unique_ptr<EVP_PKEY_CTX> ctx(common_ctx_init(), EVP_PKEY_CTX_free);
  if (!ctx) {
    return -1;
  }

  if (EVP_PKEY_encrypt_init(ctx.get()) <= 0) {
    report_exception(openssl_exception("EVP_PKEY_encrypt_init:"));
    return -1;
  }

  size_t outlen;
  if (EVP_PKEY_encrypt(ctx.get(), enc_msg, &outlen, msg, msg_len) <=
      0) { // TODO: get length with outbuf = null
    report_exception(openssl_exception("EVP_PKEY_CTX_encrypt:"));
    return -1;
  }

  return static_cast<ssize_t>(outlen); // TODO: size_t
}

ssize_t openssl_asymmetric_key_crypt::private_decrypt(
    size_t enc_msg_len, const unsigned char *enc_msg, unsigned char *dec_msg) {
  cryptcpp_unique_ptr<EVP_PKEY_CTX> ctx(common_ctx_init(), EVP_PKEY_CTX_free);
  if (!ctx) {
    return -1;
  }

  if (EVP_PKEY_decrypt_init(ctx.get()) <= 0) {
    report_exception(openssl_exception("EVP_PKEY_decrypt_init:"));
    return -1;
  }

  size_t outlen;
  if (EVP_PKEY_decrypt(ctx.get(), dec_msg, &outlen, enc_msg, enc_msg_len) <=
      0) { // TODO: get length with outbuf = null
    report_exception(openssl_exception("EVP_PKEY_CTX_decrypt:"));
    return -1;
  }

  return static_cast<ssize_t>(outlen); // TODO: size_t
}

} // namespace cryptcpp
