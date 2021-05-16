//
// Copyright 2021 Santanu Sen. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution.
//

#ifndef __CRYPTCPP_FACTORY_HPP__
#define __CRYPTCPP_FACTORY_HPP__

#include "asymmetric_key_crypt.hpp"
#include "codec.hpp"
#include "digest.hpp"
#include "digital_signature.hpp"
#include "symmetric_key_crypt.hpp"

#include <map>
#include <string>

namespace cryptcpp {

//@{
// @class factory
// An abstract factory for cryptcpp utilities.
//@}

class factory {

public:
  //@{
  // @brief returns the factory registered for a particular implementation.
  //
  // @param impl_name Name of implementation.
  // @return pointer to the factory registered or nullptr.
  //@}
  static factory *get_factory(const std::string &impl_name = "OpenSSL");

  //@{
  // @brief Returns implementation name.
  //
  // @return name of this factory implementation.
  //@}
  const std::string &get_impl_name() const { return _M_impl_name; }

  //@{
  // @brief Creates a new concrete codec.
  //
  // @param codec_algo type of the codec algorithm.
  // @return pointer to the new concrete codec.
  //@}
  virtual codec *create_codec(codec::codec_algorithm codec_algo) const = 0;

  //@{
  // @brief creates a new concrete digital_signature.
  //
  // @return pointer to the new concrete signature verifier.
  //@}
  virtual digital_signature *create_digital_signature() const = 0;

  //@{
  // @brief Creates a new concrete digest calculator.
  //
  // @return pointer to the new concrete digest calculator.
  //@}
  virtual digest *create_digest() const = 0;

  //@{
  // @brief Creates a new concrete asymmetric key crypt.
  //
  // @return pointer to the new concrete asymmetric key crypt.
  //@}
  virtual asymmetric_key_crypt *create_asymmetric_key_crypt() const = 0;

  //@{
  // @brief Creates a new concrete symmetric key crypt.
  //@}
  virtual symmetric_key_crypt *create_symmetric_key_crypt() const = 0;

  //@{
  // @brief Polymorphic base class.
  //@}
  virtual ~factory();

protected:
  //@{
  // @brief Constructor. Registers self for the given impl name.
  //
  // @param impl_name the name of this concrete factory implementation.
  // @exception throw if registration for the factory fails.
  //@}
  explicit factory(const std::string &impl_name);

private:
  // =============================================================
  //@{
  // The type of this concrete factory.
  //@}
  // =============================================================
  const std::string _M_impl_name;

  typedef std::map<std::string, factory *> factory_registry;

  //@{
  // @brief Returns a reference to the factory registry.
  // @return reference to the factory registry.
  //@}
  static factory_registry &get_factory_registry();

  //@{
  // @brief Registers a factory for a given factory implementation.
  //
  // @param impl_name factory implementation name.
  // @param factory_ptr pointer to the factory to be registered.
  // @return true on success, false on failure.
  //@}
  static bool register_factory(const std::string &impl_name,
                               factory *factory_ptr);

  //@{
  // @brief Unregisters a factory for a given factory implementation.
  //
  // @param impl_name factory implementation name.
  // @param factory_ptr pointer to the factory to be unregistered.
  // @return true on success, false on failure.
  //@}
  static bool unregister_factory(const std::string &impl_name,
                                 factory *factory_ptr);
};

} // namespace cryptcpp
#endif
