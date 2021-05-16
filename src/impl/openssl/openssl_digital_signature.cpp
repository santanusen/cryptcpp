//
// Copyright 2021 Santanu Sen. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution.
//

#include <cryptcpp/cryptcpp_util.hpp>
#include <cryptcpp/impl/openssl/openssl_digital_signature.hpp>
#include <cryptcpp/impl/openssl/openssl_exception.hpp>
#include <cryptcpp/impl/openssl/openssl_key_util.hpp>

#include <openssl/evp.h>
#include <openssl/pem.h>

namespace cryptcpp {

openssl_digital_signature::openssl_digital_signature()
    : _M_md(EVP_sha256()), _M_key(nullptr) {}

openssl_digital_signature::~openssl_digital_signature() {
  if (_M_key)
    EVP_PKEY_free(_M_key);
}

bool openssl_digital_signature::update_key(EVP_PKEY *pkey) {
  if (!pkey) {
    report_exception(openssl_exception("Could not read key:"));
    return false;
  }

  int type = EVP_PKEY_id(pkey);
  if (type == EVP_PKEY_ED25519 || type == EVP_PKEY_ED448) {
    EVP_PKEY_free(pkey);
    report_exception(openssl_exception("Key type not supported:"));
    return false;
  }

  if (_M_key) {
    EVP_PKEY_free(_M_key);
  }
  _M_key = pkey;

  return true;
}

bool openssl_digital_signature::set_key(const char *file, key_type _key_type,
                                        const char *password, size_t pass_len) {
  // Get the key envelope structure for the key file.
  EVP_PKEY *pkey =
      openssl_key_util::read_key(file, _key_type, password, pass_len);
  return update_key(pkey);
}

EVP_MD_CTX *openssl_digital_signature::common_ctx_init() {
  if (!_M_key) {
    report_exception(
        openssl_exception("openssl_digital_signature: Key not set"));
    return nullptr;
  }

  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  if (!mdctx) {
    report_exception(openssl_exception("EVP_MD_CTX_new:"));
    return nullptr;
  }
  return mdctx;
}

size_t openssl_digital_signature::sign(const unsigned char *digest,
                                       size_t digest_len,
                                       unsigned char *sign_buf,
                                       size_t sign_buf_len) {

  cryptcpp_unique_ptr<EVP_MD_CTX> mdctx(common_ctx_init(), EVP_MD_CTX_free);
  if (!mdctx) {
    return 0;
  }

  if (1 != EVP_DigestSignInit(mdctx.get(), nullptr, _M_md, nullptr, _M_key)) {
    report_exception(openssl_exception("EVP_DigestSignInit:"));
    return 0;
  }

  if (1 != EVP_DigestSignUpdate(mdctx.get(), digest, digest_len)) {
    report_exception(openssl_exception("EVP_DigestSignUpdate:"));
    return 0;
  }

  /* First call EVP_DigestSignFinal with a null sig parameter to obtain the
   * signature length. */
  size_t sign_len = sign_buf_len;
  if (1 != EVP_DigestSignFinal(mdctx.get(), nullptr, &sign_len)) {
    report_exception(openssl_exception("EVP_DigestSignFinal:"));
    return 0;
  }

  if (sign_buf_len < sign_len) {
    report_exception(openssl_exception(
        "openssl_digital_signature::sign: Insufficient buffer length"));
    return 0;
  }

  /* Now get the signature */
  if (1 != EVP_DigestSignFinal(mdctx.get(), sign_buf, &sign_len)) {
    report_exception(openssl_exception("EVP_DigestSignFinal:"));
    return 0;
  }

  return sign_len;
}

bool openssl_digital_signature::verify(const unsigned char *digest,
                                       size_t digest_len,
                                       const unsigned char *signature,
                                       size_t sign_len) {

  cryptcpp_unique_ptr<EVP_MD_CTX> mdctx(common_ctx_init(), EVP_MD_CTX_free);
  if (!mdctx) {
    return 0;
  }

  if (1 != EVP_DigestVerifyInit(mdctx.get(), nullptr, _M_md, nullptr, _M_key)) {
    report_exception(openssl_exception("EVP_DigestVerifyInit:"));
    return false;
  }

  if (1 != EVP_DigestVerifyUpdate(mdctx.get(), digest, digest_len)) {
    report_exception(openssl_exception("EVP_DigestVerifyInit:"));
    return false;
  }

  return (1 == EVP_DigestVerifyFinal(mdctx.get(), signature, sign_len));
}

bool openssl_digital_signature::set_digest_algo(
    digest::digest_algorithm digest_algo) {
  const EVP_MD *eMd = EVP_get_digestbyname(digest_algo);
  if (!eMd) {
    report_exception(openssl_exception("Unsupported Digest Algorithm:"));
    return false;
  }

  _M_md = eMd;
  return true;
}

} // namespace cryptcpp
