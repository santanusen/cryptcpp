//
// Copyright 2021 Santanu Sen. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution.
//

#ifndef __CRYPTCPP_CODEC_HPP__
#define __CRYPTCPP_CODEC_HPP__

#include "cryptcpp_cpp_std.hpp"
#include <cstdlib>

namespace cryptcpp {

//@{
// @class codec
// An interface for encoding/decoding.
//@}

class codec {

public:
  //@{
  // Codec Algorithms.
  //@}
  enum codec_algorithm { CODEC_NONE, CODEC_BASE64, CODEC_BASE64_NL, CODEC_HEX };

  //@{
  // @brief Constructor.
  //
  // @param codec_algo codec algorithm.
  //@}
  explicit codec(codec_algorithm codec_algo) : _M_codec_algo(codec_algo) {}

  //@{
  // @brief Returns the codec algorithm used.
  //
  // @return codec algorithm.
  //@}
  codec_algorithm get_algorithm() const { return _M_codec_algo; }

  //@{
  // @brief Returns maximum size of encoded data for raw data size.
  //
  // @param raw_len length of raw data.
  // @return maximum size of encoded data.
  //@}
  virtual size_t get_max_encoded_buf_len(size_t raw_len) const = 0;

  //@{
  // @brief Returns maximum size of decoded data for encoded data size.
  //
  // @param enc_len length of encoded data.
  // @return maximum size of decoded data.
  //@}
  virtual size_t get_max_decoded_buf_len(size_t enc_len) const = 0;

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
                         size_t enc_buf_len) = 0;

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
                         size_t dec_buf_len) = 0;

  //@{
  // @brief Polymorphic base class.
  //@}
  virtual ~codec() DFLTDSTR;

protected:
  //@{
  // @brief Codec algorithm.
  //@}
  const codec_algorithm _M_codec_algo;
};

} // namespace cryptcpp
#endif
