//
// Copyright 2021 Santanu Sen. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution.
//
//
// Copyright 2021 Santanu Sen. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution.
//

#ifndef __CRYPTCPP_OPENSSL_FACTORY_HPP__
#define __CRYPTCPP_OPENSSL_FACTORY_HPP__

#include <cryptcpp/factory.hpp>

namespace cryptcpp {

//@{
// @class openssl_factory
// @brief Implements factory interface for openssl implementation of utilities.
//@}

class openssl_factory : public factory {

public:
  //@{
  // @brief returns singleton factory instance.
  //
  // @return pointer to factory instance.
  //@}
  static openssl_factory &get_instance();

  //@{
  // @brief Creates a new concrete codec.
  //
  // @param codec_algo type of the codec algorithm.
  // @return pointer to the new concrete codec.
  //@}
  virtual codec *create_codec(codec::codec_algorithm codec_algo) const override;

  //@{
  // @brief creates a new concrete digital_signature.
  //
  // @return pointer to the new concrete signature verifier.
  //@}
  virtual digital_signature *create_digital_signature() const override;

  //@{
  // @brief Creates a new concrete digest calculator.
  //
  // @return pointer to the new concrete digest calculator.
  //@}
  virtual digest *create_digest() const override;

  //@{
  // @brief Creates a new concrete asymmetric key crypt.
  //
  // @return pointer to the new concrete asymmetric key crypt.
  //@}
  virtual asymmetric_key_crypt *create_asymmetric_key_crypt() const override;

  //@{
  // @brief Creates a new concrete symmetric key crypt.
  //@}
  virtual symmetric_key_crypt *create_symmetric_key_crypt() const override;

private:
  //@{
  // @brief Private constructor for singleton.
  //@}
  openssl_factory();

  //@{
  // @brief Non-copyable singleton.
  //@}
  openssl_factory(const openssl_factory &) = delete;

  //@{
  // @brief Non-copyable singleton.
  //@}
  const openssl_factory &operator=(const openssl_factory &) = delete;
};

} // namespace cryptcpp
#endif
