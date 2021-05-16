//
// Copyright 2021 Santanu Sen. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution.
//

#include <cryptcpp/impl/openssl/openssl_factory.hpp>
#include <cryptcpp/impl/openssl/openssl_std_tsp.hpp>
#include <cryptcpp/impl/openssl/openssl_thread_safety.hpp>

#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

namespace cryptcpp {

//@{
// @class openssl_initializer
// @brief Sets up openssl library and instantiates openssl crypto factory.
//@}

class openssl_initializer {

public:
  //@{
  // @brief Constructor.
  //@}
  openssl_initializer();

  //@{
  // @brief Destructor.
  //@}
  ~openssl_initializer();

private:
#ifdef OPENSSL_THREADS
  typedef openssl_thread_safety<openssl_std_mutex_thread_safety_policy>
      thread_safety_t;

  thread_safety_t thread_safety;
#endif
};

openssl_initializer::openssl_initializer() {
  // TODO: customization hook
  // Initialize the SSL library and the random number generator.
  RAND_seed("7&a4$#2;:(*+=", 13);
  SSL_library_init();
  SSL_load_error_strings();
  OpenSSL_add_all_algorithms();
  RAND_load_file("/dev/urandom", 1024);

  // Instantiate factory; get it registered.
  openssl_factory::get_instance();
}

openssl_initializer::~openssl_initializer() {
  // Cleanup the SSL library.
  // ERR_remove_state(0);
  // ERR_remove_thread_state(nullptr);
  EVP_cleanup();
  CRYPTO_cleanup_all_ex_data();
  ERR_free_strings();
  ENGINE_cleanup();
  CONF_modules_unload(1);
  CONF_modules_free();
  // sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
}

//@{
// @brief A global instance of openssl_initializer. Makes sure that SSL library
// is initialized and the crypto factory instance is registered before
// the application starts invoking its APIs.
//@}

openssl_initializer global_openssl_initializer_instance;

} // namespace cryptcpp
