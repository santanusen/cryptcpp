//
// Copyright 2021 Santanu Sen. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution.
//

#ifndef __CRYPTCPP_UTIL_HPP__
#define __CRYPTCPP_UTIL_HPP__

#if __cplusplus > 201100L
#include <functional>
#include <memory>
#endif

#include "cryptcpp_cpp_std.hpp"

namespace cryptcpp {

#if __cplusplus > 201100L
template <typename T>
using cryptcpp_unique_ptr = std::unique_ptr<T, std::function<void(T *)>>;
#else
//@{
// @class cryptcpp_unique_ptr
//
// @brief This is a simple auto pointer template for exception safe
// cleanup of crypto structures with custom cleanup functions.
//
// @tparam _T type of pointer
// @param _DelFunc type of Deletion function
//@}
template <typename _T, typename _DelFunc = void (*)(_T *)>
class cryptcpp_unique_ptr {

private:
  _T *_M_ptr;

  _DelFunc _M_del_func;

public:
  //@{
  // Constructor.
  //
  // @param ptr the object pointer.
  // @param del_func the cleanup function.
  //@}
  explicit cryptcpp_unique_ptr(_T *ptr, _DelFunc del_func = nullptr)
      : _M_ptr(ptr), _M_del_func(del_func) {}

  //@{
  // Destructor.
  //
  // @brief Cleans up the pointer with deletion function.
  //@}
  ~cryptcpp_unique_ptr() {
    if (_M_ptr) {
      if (_M_del_func) {
        _M_del_func(_M_ptr);
      }
    }
  }

  //@{
  // Pointer retrieval.
  //@}
  inline _T *get() { return _M_ptr; }

  inline const _T *get() const { return _M_ptr; }

  _T *release() {
    _T *ptr = _M_ptr;
    _M_ptr = nullptr;
    return ptr;
  }

  //@{
  // Operators.
  //@}
  inline _T *operator->() { return _M_ptr; }

  inline const _T *operator->() const { return _M_ptr; }

  inline _T &operator*() { return *_M_ptr; }

  inline const _T &operator*() const { return *_M_ptr; }

  inline operator bool() const { return (_M_ptr != nullptr); }

private:
  //@{
  // Non-copyable.
  //@}
  cryptcpp_unique_ptr() DELETED;

  cryptcpp_unique_ptr(const cryptcpp_unique_ptr &) DELETED;

  cryptcpp_unique_ptr &operator=(const cryptcpp_unique_ptr &) DELETED;
};
#endif

} // namespace cryptcpp
#endif
