//
// Copyright 2021 Santanu Sen. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution.
//

#include <cryptcpp/impl/openssl/openssl_std_tsp.hpp>

namespace cryptcpp {

std::mutex *openssl_std_mutex_thread_safety_policy::_S_static_mutex_buf =
    nullptr;

openssl_std_mutex_thread_safety_policy::openssl_std_mutex_thread_safety_policy(
    int num_locks) {
  openssl_std_mutex_thread_safety_policy::_S_static_mutex_buf =
      new std::mutex[num_locks];
}

openssl_std_mutex_thread_safety_policy::
    ~openssl_std_mutex_thread_safety_policy() {
  delete[](_S_static_mutex_buf);
}

void openssl_std_mutex_thread_safety_policy::lock(int num) {
  _S_static_mutex_buf[num].lock();
}

void openssl_std_mutex_thread_safety_policy::unlock(int num) {
  _S_static_mutex_buf[num].unlock();
}

openssl_std_mutex_thread_safety_policy::CRYPTO_dynlock_value *
openssl_std_mutex_thread_safety_policy::dynamic_lock_create() {
  return (new CRYPTO_dynlock_value());
}

void openssl_std_mutex_thread_safety_policy::dynamic_lock(
    openssl_std_mutex_thread_safety_policy::CRYPTO_dynlock_value *dyn_lock) {
  dyn_lock->_M_mutex.lock();
}

void openssl_std_mutex_thread_safety_policy::dynamic_unlock(
    openssl_std_mutex_thread_safety_policy::CRYPTO_dynlock_value *dyn_lock) {
  dyn_lock->_M_mutex.unlock();
}

void openssl_std_mutex_thread_safety_policy::dynamic_lock_destroy(
    openssl_std_mutex_thread_safety_policy::CRYPTO_dynlock_value *dyn_lock) {
  delete dyn_lock;
}

} // namespace cryptcpp
