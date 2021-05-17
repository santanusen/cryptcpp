//
// Copyright 2021 Santanu Sen. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution.
//

#ifndef __CRYPTCPP_OPENSSL_STD_THREAD_SAFETY_POLICY_HPP__
#define __CRYPTCPP_OPENSSL_STD_THREAD_SAFETY_POLICY_HPP__

#include <cryptcpp/cryptcpp_cpp_std.hpp>
#include <mutex>

namespace cryptcpp {

//@{
// @class openssl_std_mutex_thread_safety_policy
// @brief Implements locking policy for openssl thread safety using std::mutex
// @}
class openssl_std_mutex_thread_safety_policy {

  // Only the host class needs to access the member functions.
protected:
  //@{
  // @brief opaque structure for OpenSSL dynamic locking callbacks.
  //@}
  struct CRYPTO_dynlock_value {
    std::mutex _M_mutex;
  };

  //@{
  // @brief Mutex buffer for openssl static locking callbacks.
  //@}
  static std::mutex *_S_static_mutex_buf;

  openssl_std_mutex_thread_safety_policy(int num_locks);

  ~openssl_std_mutex_thread_safety_policy();

  static void lock(int num);

  static void unlock(int num);

  static CRYPTO_dynlock_value *dynamic_lock_create();

  static void dynamic_lock(CRYPTO_dynlock_value *dyn_lock);

  static void dynamic_unlock(CRYPTO_dynlock_value *dyn_lock);

  static void dynamic_lock_destroy(CRYPTO_dynlock_value *dyn_lock);

private:
  // Non-copyable
  openssl_std_mutex_thread_safety_policy(
      const openssl_std_mutex_thread_safety_policy &) DELETED;

  openssl_std_mutex_thread_safety_policy &
  operator=(const openssl_std_mutex_thread_safety_policy &) DELETED;
};

} // namespace cryptcpp

#endif
