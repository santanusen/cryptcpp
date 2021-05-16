//
// Copyright 2021 Santanu Sen. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution.
//

#include <cryptcpp/cryptcpp_util.hpp>
#include <cryptcpp/impl/openssl/openssl_codec_base64.hpp>
#include <cryptcpp/impl/openssl/openssl_exception.hpp>

#include <openssl/bio.h>
#include <openssl/evp.h>

#include <algorithm>
#include <cstring>

namespace cryptcpp {

size_t openssl_codec_base64::get_max_encoded_buf_len(size_t raw_len) const {
  return ((((4 * raw_len / 3) + 3) & ~3) + 1);
}

size_t openssl_codec_base64::get_max_decoded_buf_len(size_t enc_len) const {
  return (((enc_len * 6 + 7) / 8) + 1);
}

ssize_t openssl_codec_base64::encode(const char *raw_buf, size_t raw_len,
                                     char *enc_buf, size_t enc_buf_len) {

  // Create a BIO base64 filter.
  // Ensure exception safe cleanup.
  cryptcpp_unique_ptr<BIO> b64(BIO_new(BIO_f_base64()), BIO_free_all);
  if (!b64) {
    report_exception(openssl_exception("BIO_new(BIO_f_base64()):"));
    return -1;
  }

  BIO *b64_chain = b64.get();

  if (_M_codec_algo != CODEC_BASE64_NL) {
    BIO_set_flags(b64_chain, BIO_FLAGS_BASE64_NO_NL);
  }

  // Append a BIO memory buffer to the base64 filter.
  BIO *bmem = BIO_new(BIO_s_mem());
  if (!bmem) {
    report_exception(openssl_exception("BIO_new(BIO_s_mem()):"));
    return -1;
  }
  b64_chain = BIO_push(b64_chain, bmem);

  // Write the input data into the BIO chain.
  BIO_write(b64_chain, raw_buf, raw_len);
  if (1 != BIO_flush(b64_chain)) {
    report_exception(openssl_exception("BIO_flush"));
    return -1;
  }

  // Read the encoded data back from the BIO chain.
  char *dt = nullptr;
  const ssize_t enc_len = BIO_get_mem_data(b64_chain, &dt);
  const ssize_t out_len = std::min(enc_len, static_cast<ssize_t>(enc_buf_len));
  memcpy(enc_buf, dt, out_len);
  if (static_cast<size_t>(out_len) < enc_buf_len) {
    enc_buf[out_len] = '\0';
  }

  return out_len;
}

ssize_t openssl_codec_base64::decode(const char *enc_buf, size_t enc_len,
                                     char *dec_buf, size_t dec_buf_len) {
  // Create a BIO base64 filter.
  // Ensure exception safe cleanup.
  cryptcpp_unique_ptr<BIO> b64(BIO_new(BIO_f_base64()), BIO_free_all);
  if (!b64) {
    report_exception(openssl_exception("BIO_new(BIO_f_base64()):"));
    return -1;
  }

  BIO *b64_chain = b64.get();

  if (_M_codec_algo != CODEC_BASE64_NL) {
    BIO_set_flags(b64_chain, BIO_FLAGS_BASE64_NO_NL);
  }

  // Append a BIO memory buffer containing the input to the base64 filter.
  BIO *bmem = BIO_new_mem_buf(enc_buf, enc_len);
  if (!bmem) {
    report_exception(openssl_exception("BIO_new(BIO_s_mem()):"));
    return -1;
  }
  b64_chain = BIO_push(b64_chain, bmem);

  // Read back decoded data through the chain.
  return BIO_read(b64_chain, dec_buf, dec_buf_len);
}

} // namespace cryptcpp
