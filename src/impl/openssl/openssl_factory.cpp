//
// Copyright 2021 Santanu Sen. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution.
//

#include <cryptcpp/impl/openssl/openssl_factory.hpp>

#include <cryptcpp/impl/openssl/openssl_asymmetric_key_crypt.hpp>
#include <cryptcpp/impl/openssl/openssl_codec_base64.hpp>
#include <cryptcpp/impl/openssl/openssl_codec_hex.hpp>
#include <cryptcpp/impl/openssl/openssl_digest.hpp>
#include <cryptcpp/impl/openssl/openssl_digital_signature.hpp>
#include <cryptcpp/impl/openssl/openssl_symmetric_key_crypt.hpp>

namespace cryptcpp {

openssl_factory &openssl_factory::get_instance() {
  static openssl_factory _S_instance;
  return _S_instance;
}

openssl_factory::openssl_factory() : factory("OpenSSL") {}

// Creation functions for concrete cryptographic component implementations.

codec *openssl_factory::create_codec(codec::codec_algorithm codec_algo) const {
  switch (codec_algo) {
  case codec::CODEC_BASE64:
  case codec::CODEC_BASE64_NL:
    return new openssl_codec_base64(codec_algo);

  case codec::CODEC_HEX:
    return new openssl_codec_hex(codec_algo);

  default:
    return nullptr;
  }
}

digital_signature *openssl_factory::create_digital_signature() const {
  return new openssl_digital_signature();
}

digest *openssl_factory::create_digest() const { return new openssl_digest(); }

asymmetric_key_crypt *openssl_factory::create_asymmetric_key_crypt() const {
  return new openssl_asymmetric_key_crypt();
}

symmetric_key_crypt *openssl_factory::create_symmetric_key_crypt() const {
  return new openssl_symmetric_key_crypt();
}

} // namespace cryptcpp
