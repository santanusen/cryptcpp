//
// Copyright 2021 Santanu Sen. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution.
//

#if __cplusplus < 201100L
#include <cryptcpp/impl/openssl/openssl_posix_tsp.hpp>

namespace cryptcpp {

pthread_mutex_t *openssl_posix_mutex_thread_safety_policy::_S_static_mutex_buf =
    nullptr;

int openssl_posix_mutex_thread_safety_policy::_S_static_mutex_buf_sz = 0;

openssl_posix_mutex_thread_safety_policy::
    openssl_posix_mutex_thread_safety_policy(int num_locks) {
  openssl_posix_mutex_thread_safety_policy::_S_static_mutex_buf =
      new pthread_mutex_t[num_locks];
  openssl_posix_mutex_thread_safety_policy::_S_static_mutex_buf_sz = num_locks;
  for (int i = 0; i < num_locks; ++i) {
    pthread_mutex_init(
        &openssl_posix_mutex_thread_safety_policy::_S_static_mutex_buf[i],
        nullptr);
  }
}

openssl_posix_mutex_thread_safety_policy::
    ~openssl_posix_mutex_thread_safety_policy() {
  for (int i = 0;
       i < openssl_posix_mutex_thread_safety_policy::_S_static_mutex_buf_sz;
       ++i) {
    pthread_mutex_destroy(
        &openssl_posix_mutex_thread_safety_policy::_S_static_mutex_buf[i]);
  }
  openssl_posix_mutex_thread_safety_policy::_S_static_mutex_buf_sz = 0;
  delete[](_S_static_mutex_buf);
}

void openssl_posix_mutex_thread_safety_policy::lock(int num) {
  pthread_mutex_lock(&_S_static_mutex_buf[num]);
}

void openssl_posix_mutex_thread_safety_policy::unlock(int num) {
  pthread_mutex_unlock(&_S_static_mutex_buf[num]);
}

openssl_posix_mutex_thread_safety_policy::CRYPTO_dynlock_value *
openssl_posix_mutex_thread_safety_policy::dynamic_lock_create() {
  CRYPTO_dynlock_value *dyn_lock = new CRYPTO_dynlock_value;
  pthread_mutex_init(&dyn_lock->_M_mutex, nullptr);
  return dyn_lock;
}

void openssl_posix_mutex_thread_safety_policy::dynamic_lock(
    openssl_posix_mutex_thread_safety_policy::CRYPTO_dynlock_value *dyn_lock) {
  pthread_mutex_lock(&dyn_lock->_M_mutex);
}

void openssl_posix_mutex_thread_safety_policy::dynamic_unlock(
    openssl_posix_mutex_thread_safety_policy::CRYPTO_dynlock_value *dyn_lock) {
  pthread_mutex_unlock(&dyn_lock->_M_mutex);
}

void openssl_posix_mutex_thread_safety_policy::dynamic_lock_destroy(
    openssl_posix_mutex_thread_safety_policy::CRYPTO_dynlock_value *dyn_lock) {
  pthread_mutex_destroy(&dyn_lock->_M_mutex);
  delete dyn_lock;
}

} // namespace cryptcpp
#endif // C++98
