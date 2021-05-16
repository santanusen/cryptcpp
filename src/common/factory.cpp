//
// Copyright 2021 Santanu Sen. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution.
//

#include <cryptcpp/crypt_exception.hpp>
#include <cryptcpp/factory.hpp>

namespace cryptcpp {

factory::factory_registry &factory::get_factory_registry() {
  // Static object in function scope to maintain initialization order.
  static factory_registry _S_factory_registry;
  return _S_factory_registry;
}

factory *factory::get_factory(const std::string &impl_name) {
  factory_registry &registry = get_factory_registry();
  factory_registry::iterator it = registry.find(impl_name);
  return ((it == registry.end() ? nullptr : it->second));
}

bool factory::register_factory(const std::string &impl_name,
                               factory *factory_ptr) {
  // Return the result of insertion into map.
  return ((get_factory_registry())
              .insert(factory_registry::value_type(impl_name, factory_ptr)))
      .second;
}

bool factory::unregister_factory(const std::string &impl_name,
                                 factory *factory_ptr) {
  factory_registry &registry = get_factory_registry();
  factory_registry::iterator it = registry.find(impl_name);

  if (it == registry.end() || it->second != factory_ptr) {
    return false;
  }

  registry.erase(it);
  return true;
}

factory::factory(const std::string &impl_name) : _M_impl_name(impl_name) {
  // Auto-registration in constructor.
  if (!register_factory(impl_name, this)) {
    report_exception(crypt_exception(
        std::string("Factory already instantiated: ") + impl_name));
  }
}

factory::~factory() {
  // Auto-unregistration in destructor.
  unregister_factory(_M_impl_name, this);
}

} // namespace cryptcpp
