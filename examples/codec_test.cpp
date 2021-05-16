//
// Copyright 2021 Santanu Sen. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution.
//

#include <cryptcpp/factory.hpp>
#include <iostream>
#include <memory>
#include <string>

void codec_test(const std::string &raw,
                cryptcpp::codec::codec_algorithm codec_algo,
                const std::string &test_name) {
  std::cout << std::endl
            << "____________________________________________________"
            << std::endl;
  // Create the codec utility through factory.
  auto fact = cryptcpp::factory::get_factory();
  std::shared_ptr<cryptcpp::codec> my_codec(fact->create_codec(codec_algo));

  // Encode the raw string.
  const size_t enc_buf_len = my_codec->get_max_encoded_buf_len(raw.size());
  char enc_buf[enc_buf_len + 1];
  const size_t enc_len =
      my_codec->encode(raw.c_str(), raw.size(), enc_buf, enc_buf_len);
  enc_buf[enc_len] = '\0';
  std::cout << test_name << " encoded buffer length: " << enc_buf_len
            << " encoded data length: " << enc_len << " data:" << std::endl
            << enc_buf << std::endl;

  // Decode the encoded string back.
  const size_t dec_buf_len = my_codec->get_max_decoded_buf_len(enc_len);
  char dec_buf[dec_buf_len];
  const size_t dec_len =
      my_codec->decode(enc_buf, enc_len, dec_buf, dec_buf_len);
  dec_buf[dec_len] = '\0';
  std::cout << test_name << " decoded buffer length: " << dec_buf_len
            << " decoded data length: " << dec_len << " data:" << std::endl
            << dec_buf << std::endl;
}

int main() {
  std::string raw = "A quick brown fox jumped over a lazy dog!";
  codec_test(raw, cryptcpp::codec::CODEC_BASE64, "BASE64");
  codec_test(raw, cryptcpp::codec::CODEC_BASE64_NL, "BASE64_NL");
  codec_test(raw, cryptcpp::codec::CODEC_HEX, "HEX");

  return 0;
}
