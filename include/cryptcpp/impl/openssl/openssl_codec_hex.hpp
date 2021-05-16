//
// Copyright 2021 Santanu Sen. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution.
//

#ifndef __CRYPTCPP_OPENSSL_CODEC_HEX_HPP__
#define __CRYPTCPP_OPENSSL_CODEC_HEX_HPP__

#include <cryptcpp/codec.hpp>

namespace cryptcpp {

// =====================================================================
//@{
// This class implements the codec interface for Base-64
// encoding/decoding using OpenSSL routines.
//@}
// =====================================================================

class openssl_codec_hex : public codec {

public:
  //@{
  // @brief Constructor.
  // @param codec_algo type of the codec.
  //@}
  explicit openssl_codec_hex(codec_algorithm codec_algo) : codec(codec_algo) {}

  //@{
  // @brief Returns maximum size of encoded data for raw data size.
  //
  // @param raw_len length of raw data.
  // @return maximum size of encoded data.
  //@}
  size_t get_max_encoded_buf_len(size_t raw_len) const override;

  //@{
  // @brief Returns maximum size of decoded data for encoded data size.
  //
  // @param enc_len length of encoded data.
  // @return maximum size of decoded data.
  //@}
  size_t get_max_decoded_buf_len(size_t enc_len) const override;

  //@{
  // @brief Performs encoding.
  //
  // @param raw_buf the input data to be encoded.
  // @param raw_len the length of the input data.
  // @param enc_buf output buffer to write encoded data.
  // @param enc_buf_len the length of the output buffer.
  // @return length of encoded data, negative on error.
  //@}
  virtual ssize_t encode(const char *raw_buf, size_t raw_len, char *enc_buf,
                         size_t enc_buf_len) override;

  //@{
  // @brief Performs decoding.
  //
  // @param enc_buf the input data to be decoded.
  // @param enc_len the length of the input data.
  // @param dec_buf output buffer to write decoded data.
  // @param dec_buf_len the length of the output buffer.
  // @return length of the decoded data, negative on error.
  //@}
  virtual ssize_t decode(const char *enc_buf, size_t enc_len, char *dec_buf,
                         size_t dec_buf_len) override;
};

} // namespace cryptcpp
#endif
