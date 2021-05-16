//
// Copyright 2021 Santanu Sen. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution.
//

#ifndef __CRYPTCPP_OPENSSL_THREAD_SAFETY_HPP__
#define __CRYPTCPP_OPENSSL_THREAD_SAFETY_HPP__

#define OPENSSL_THREAD_DEFINES
#include <openssl/opensslconf.h>

#ifdef OPENSSL_THREADS
#include <openssl/crypto.h>

namespace cryptcpp {

//@{
// @class openssl_thread_safety
// @brief Host class for registering openssl locking callbacks.
// @tparam _T_thread_safety_policy policy class for implementing a locking
// scheme.
// @}
template <class _T_thread_safety_policy>
class openssl_thread_safety : public _T_thread_safety_policy {

private:
  //@{
  // @brief Static locking callback.
  //
  // @param mode lock/unlock mode.
  // @param num index of the mutex in static mutex buffer.
  // @param file file name of the calling function - ignored.
  // @param line line number of the calling function - ignored.
  //@}
  static void locking_callback(int mode, int num, const char * /*file*/,
                               int /*line*/) {
    if ((mode & CRYPTO_LOCK)) {
      _T_thread_safety_policy::lock(num);
    } else {
      _T_thread_safety_policy::unlock(num);
    }
  }

  //@{
  // @brief Dynamic lock creation callback function.
  //
  // @param file file name of the calling function - ignored.
  // @param line line number of the calling function - ignored.
  // @return pointer to the newly created dynamic lock structure.
  //@}
  static typename _T_thread_safety_policy::CRYPTO_dynlock_value *
  dynamic_lock_create_callback(const char * /*file*/, int /*line*/) {
    return _T_thread_safety_policy::dynamic_lock_create();
  }

  //@{
  // @brief Dynamic locking callback.
  //
  // @param mode lock/unlock mode.
  // @param dyn_lock pointer to the dynamic lock structure.
  // @param file file name of the calling function - ignored.
  // @param line line number of the calling function - ignored.
  //@}
  static void dynamic_locking_callback(
      int mode,
      typename _T_thread_safety_policy::CRYPTO_dynlock_value *dyn_lock,
      const char * /*file*/, int /*line*/) {
    if ((mode & CRYPTO_LOCK)) {
      _T_thread_safety_policy::dynamic_lock(dyn_lock);
    } else {
      _T_thread_safety_policy::dynamic_unlock(dyn_lock);
    }
  }

  //@{
  // @brief Dynamic lock deletion callback.
  //
  // @param dyn_lock pointer to the dynamic lock structure.
  // @param file file name of the calling function - ignored.
  // @param line line number of the calling function - ignored.
  //@}
  static void dynamic_lock_destroy(
      typename _T_thread_safety_policy::CRYPTO_dynlock_value *dyn_lock,
      const char * /*file*/, int /*line*/) {
    _T_thread_safety_policy::dynamic_lock_destroy(dyn_lock);
  }

public:
  //@{
  // @brief Sets up thread safety by initializing the
  // static mutex buffer and registering locking callbacks.
  //@}
  openssl_thread_safety() : _T_thread_safety_policy(CRYPTO_num_locks()) {
    // Register the static locking callback.
    CRYPTO_set_locking_callback(locking_callback);

    // Register the dynamic locking callbacks.
    CRYPTO_set_dynlock_create_callback(dynamic_lock_create);
    CRYPTO_set_dynlock_lock_callback(dynamic_locking_callback);
    CRYPTO_set_dynlock_destroy_callback(dynamic_lock_destroy);
  }

  //@{
  // @brief Deallocates the static mutex buffer and unregisters
  // the locking callbacks.
  //@}
  ~openssl_thread_safety() {
    // Unregister the dynamic locking callbacks.
    CRYPTO_set_dynlock_destroy_callback(nullptr);
    CRYPTO_set_dynlock_lock_callback(nullptr);
    CRYPTO_set_dynlock_create_callback(nullptr);

    // Cleanup and free mutexes for static locking operations.
    CRYPTO_set_locking_callback(nullptr);
  }
};
} // namespace cryptcpp
#endif
#endif
