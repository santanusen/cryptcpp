//
// Copyright 2021 Santanu Sen. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution.
//

#include <cryptcpp/cryptcpp_util.hpp>
#include <cryptcpp/impl/openssl/openssl_exception.hpp>
#include <cryptcpp/impl/openssl/openssl_key_util.hpp>

#include <openssl/evp.h>
#include <openssl/store.h>
#include <openssl/ui.h>

#include <cstring>

namespace cryptcpp {

namespace cryptcpp_ui {

struct pw_cb_data {
  const char *password;
  size_t pass_len;
};

static int cryptcpp_ui_reader(UI *ui, UI_STRING *uis) {

  pw_cb_data *cb_data = static_cast<pw_cb_data *>(UI_get0_user_data(ui));

  if ((UI_get_input_flags(uis) & UI_INPUT_FLAG_DEFAULT_PWD) && (cb_data)) {
    switch (UI_get_string_type(uis)) {
    case UIT_PROMPT:
    case UIT_VERIFY: {
      if (cb_data->password != NULL) {
        UI_set_result_ex(ui, uis, cb_data->password, cb_data->pass_len);
        return 1;
      }
    } break;
    case UIT_NONE:
    case UIT_BOOLEAN:
    case UIT_INFO:
    case UIT_ERROR:
    default:
      break;
    }
  }

  /* Default to the empty password. */
  UI_set_result(ui, uis, "");
  return 1;
}

static UI_METHOD *get_method() {
  UI_METHOD *method = UI_create_method("CryptCPP");
  if (!method) {
    report_exception(openssl_exception("UI_create_method:"));
    return nullptr;
  }

  UI_method_set_reader(method, cryptcpp_ui_reader);
  return method;
}

} // namespace cryptcpp_ui

EVP_PKEY *openssl_key_util::read_key(const char *uri,
                                     asymmetric_key::key_type _key_type,
                                     const char *password, size_t pass_len) {
  if (!uri) {
    report_exception(openssl_exception("No Key uri specified."));
    return nullptr;
  }

  cryptcpp_unique_ptr<UI_METHOD> ui_method(cryptcpp_ui::get_method(),
                                           UI_destroy_method);
  if (!ui_method) {
    return nullptr;
  }

  cryptcpp_ui::pw_cb_data ui_data{password, pass_len};
  cryptcpp_unique_ptr<OSSL_STORE_CTX> ctx(
      OSSL_STORE_open(uri, ui_method.get(), &ui_data, nullptr, nullptr),
      OSSL_STORE_close);
  if (!ctx) {
    report_exception(openssl_exception("OSSL_STORE_open:"));
    return nullptr;
  }

  while (!OSSL_STORE_eof(ctx.get())) {
    cryptcpp_unique_ptr<OSSL_STORE_INFO> info(OSSL_STORE_load(ctx.get()),
                                              OSSL_STORE_INFO_free);
    if (!info) {
      report_exception(openssl_exception("OSSL_STORE_load:"));
      return nullptr;
    }

    const int type = OSSL_STORE_INFO_get_type(info.get());
    if (asymmetric_key::ASYM_KEY_PUBLIC == _key_type) {
      if (OSSL_STORE_INFO_PUBKEY == type) {
        if (EVP_PKEY *pkey = OSSL_STORE_INFO_get1_PUBKEY(info.get())) {
          return pkey;
        }
        report_exception(openssl_exception("OSSL_STORE_INFO_get1_PUBKEY:"));
        return nullptr;
      } else if (OSSL_STORE_INFO_PUBKEY == type) {
        /* Extract public key from private key info. */
        if (OSSL_STORE_INFO_get1_PKEY(info.get())) { // Privatet Key
          if (EVP_PKEY *pkey =
                  OSSL_STORE_INFO_get1_PKEY(info.get())) { // Public Key
            return pkey;
          }
        }
        report_exception(openssl_exception("OSSL_STORE_INFO_get1_PKEY:"));
        return nullptr;
      }
    } else if (OSSL_STORE_INFO_PUBKEY == type) {
      if (EVP_PKEY *pkey = OSSL_STORE_INFO_get1_PKEY(info.get())) {
        return pkey;
      }
      report_exception(openssl_exception("OSSL_STORE_INFO_get1_PKEY:"));
      return nullptr;
    }
  }

  report_exception(openssl_exception("Could not read key"));
  return nullptr;
}

} // namespace cryptcpp
