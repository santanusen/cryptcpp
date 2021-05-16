//
// Copyright 2021 Santanu Sen. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution.
//

#include <cryptcpp/cryptcpp_util.hpp>
#include <cryptcpp/impl/openssl/openssl_codec_hex.hpp>
#include <cryptcpp/impl/openssl/openssl_exception.hpp>

#include <openssl/bn.h>

#include <algorithm>
#include <cstring>

namespace cryptcpp {

size_t openssl_codec_hex::get_max_encoded_buf_len(size_t raw_len) const {
  return (raw_len * 2 + 1);
}

size_t openssl_codec_hex::get_max_decoded_buf_len(size_t enc_len) const {
  return (enc_len / 2 + 1);
}

ssize_t openssl_codec_hex::encode(const char *raw_buf, size_t raw_len,
                                  char *enc_buf, size_t enc_buf_len) {
  // Convert input data to big number.
  // Ensure exception safe cleanup.
  cryptcpp_unique_ptr<BIGNUM> big_num(
      BN_bin2bn(reinterpret_cast<const unsigned char *>(raw_buf), raw_len,
                nullptr),
      BN_free);
  if (!big_num) {
    report_exception(openssl_exception("BN_bin2bn:"));
    return -1;
  }

  // Convert big number to hex string.
  char *hex_rep = BN_bn2hex(big_num.get());
  if (!hex_rep) {
    report_exception(openssl_exception("BN_bn2hex:"));
    return -1;
  }

  const size_t out_len = std::min(enc_buf_len, strlen(hex_rep));
  memcpy(enc_buf, hex_rep, out_len);
  if (out_len < enc_buf_len) {
    enc_buf[out_len] = '\0';
  }

  OPENSSL_free(hex_rep);

  return out_len;
}

ssize_t openssl_codec_hex::decode(const char *enc_buf, size_t /*enc_len*/,
                                  char *dec_buf, size_t dec_buf_len) {
  BIGNUM *big_num_ptr = nullptr;

  // Convert hex string to big number.
  if (BN_hex2bn(&big_num_ptr, enc_buf) == 0) {
    report_exception(openssl_exception("BN_hex2bn:"));
    return -1;
  }

  // Ensure exception safe cleanup.
  cryptcpp_unique_ptr<BIGNUM> big_num(big_num_ptr, BN_free);

  if (static_cast<int>(dec_buf_len) < BN_num_bytes(big_num.get())) {
    report_exception(
        openssl_exception("decode: Insufficent output buffer length"));
    return -1;
  }
  // Convert big number to hex string.
  const ssize_t dec_len =
      BN_bn2bin(big_num.get(), reinterpret_cast<unsigned char *>(dec_buf));

  return dec_len;
}

} // namespace cryptcpp
