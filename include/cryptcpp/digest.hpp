//
// Copyright 2021 Santanu Sen. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution.
//

#ifndef __CRYPTCPP_DIGEST_HPP__
#define __CRYPTCPP_DIGEST_HPP__

#include "cryptcpp_cpp_std.hpp"
#include <cstdlib>

namespace cryptcpp {

//@{
// @class digest
// Interface for digest/hash calculation.
//@}

class digest {

public:
  //@{
  // @brief Types of digest calculation algorithms.
  //@}
  typedef const char *digest_algorithm;
  static inline digest_algorithm DIGEST_MD2() { return "MD2"; }
  static inline digest_algorithm DIGEST_MD5() { return "MD5"; }
  static inline digest_algorithm DIGEST_SHA() { return "SHA"; }
  static inline digest_algorithm DIGEST_SHA1() { return "SHA1"; }
  static inline digest_algorithm DIGEST_SHA224() { return "SHA224"; }
  static inline digest_algorithm DIGEST_SHA256() { return "SHA256"; }
  static inline digest_algorithm DIGEST_SHA384() { return "SHA384"; }
  static inline digest_algorithm DIGEST_SHA512() { return "SHA512"; }
  static inline digest_algorithm DIGEST_MDC2() { return "MDC2"; }
  static inline digest_algorithm DIGEST_RIPEMD160() { return "RIPEMD160"; }

  //@{
  // Polymorphic base class.
  //@}
  virtual ~digest() DFLTDSTR;

  //@{
  // @brief Calculates the digest of the given data.
  //
  // @param data input data whose digest is to be calculated.
  // @param data_len length of input data.
  // @param digest_buffer output buffer to write calculated digest.
  // @param digest_buf_len maximum size of the output buffer.
  // @return length of the digest.
  //@}
  virtual size_t calculate_digest(const unsigned char *data, size_t data_len,
                                  unsigned char *digest_buf,
                                  size_t digest_buf_len) = 0;

  //@{
  // @brief Sets the digest calculation algorithm to use.
  // @param _digest_algorithm the digest calculation algorithm to use.
  // @return true if successful.
  //@}
  virtual bool set_digest_algorithm(digest_algorithm digest_algo) = 0;
};

} // namespace cryptcpp
#endif
