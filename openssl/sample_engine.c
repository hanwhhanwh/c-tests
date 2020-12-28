/**
 * OpenSSL sample engine
 * @author hbesthee@naver.com
 * @date 2020-12-28
 * reference : https://www.sinodun.com/2009/02/developing-an-engine-for-openssl/
 */
#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/engine.h>

static int bind_fn(ENGINE * e, const char *id)
{
  if (!ENGINE_set_id(e, "sample") ||
      !ENGINE_set_name(e, "sample engine")) {
    return 0;
  } else {
    return 1;
  }
}

IMPLEMENT_DYNAMIC_CHECK_FN();
IMPLEMENT_DYNAMIC_BIND_FN(bind_fn);
