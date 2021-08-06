#ifndef CRYPTO_HMAC_H_
#define CRYPTO_HMAC_H_

#include <stdio.h>
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <gnutls/crypto.h>

#define hmac_hash(algorithm, key, key_len, msg, cb_msg, digest) gnutls_hmac_fast(algorithm, key, key_len, msg, cb_msg, digest)
#define hmac_sha256_hash(key, key_len, msg, cb_msg, digest) hmac_hash(GNUTLS_MAC_SHA256, key, key_len, msg, cb_msg, digest)
#define hmac_sha512_hash(key, key_len, msg, cb_msg, digest)   hmac_hash(GNUTLS_MAC_SHA512, key, key_len, msg, cb_msg, digest)

typedef struct hmac_ctx 
{
	gnutls_hmac_hd_t handle;
}hmac_ctx_t, hmac_sha256_t, hmac_sha512_t, hmac_ripemd_t;

#define hmac_init(ctx, algorithm, key, key_len) gnutls_hmac_init(&ctx->handle, algorithm, key, key_len)
#define hmac_update(ctx, msg, cb_msg) gnutls_hmac(ctx->handle, msg, cb_msg)
#define hmac_final(ctx, digest) gnutls_hmac_deinit(ctx->handle, digest)


#define hmac_sha1_init(ctx  , key, key_len) hmac_init(ctx, GNUTLS_MAC_SHA1, key, key_len)
#define hmac_sha224_init(ctx, key, key_len) hmac_init(ctx, GNUTLS_MAC_SHA224, key, key_len)
#define hmac_sha256_init(ctx, key, key_len) hmac_init(ctx, GNUTLS_MAC_SHA256, key, key_len)
#define hmac_sha384_init(ctx, key, key_len) hmac_init(ctx, GNUTLS_MAC_SHA384, key, key_len)
#define hmac_sha512_init(ctx, key, key_len) hmac_init(ctx, GNUTLS_MAC_SHA512, key, key_len)
#define hmac_ripemd_init(ctx, key, key_len) hmac_init(ctx, GNUTLS_MAC_RMD160, key, key_len)

#define hmac_sha1_update(ctx, msg, cb_msg)   hmac_update(ctx, msg, cb_msg);
#define hmac_sha224_update(ctx, msg, cb_msg) hmac_update(ctx, msg, cb_msg)
#define hmac_sha256_update(ctx, msg, cb_msg) hmac_update(ctx, msg, cb_msg)
#define hmac_sha384_update(ctx, msg, cb_msg) hmac_update(ctx, msg, cb_msg)
#define hmac_sha512_update(ctx, msg, cb_msg) hmac_update(ctx, msg, cb_msg)
#define hmac_ripemd_update(ctx, msg, cb_msg) hmac_update(ctx, msg, cb_msg)

#define hmac_sha1_final(ctx, digest)   hmac_final(ctx, digest)
#define hmac_sha224_final(ctx, digest) hmac_final(ctx, digest)
#define hmac_sha256_final(ctx, digest) hmac_final(ctx, digest)
#define hmac_sha384_final(ctx, digest) hmac_final(ctx, digest)
#define hmac_sha512_final(ctx, digest) hmac_final(ctx, digest)
#define hmac_ripemd_final(ctx, digest) hmac_final(ctx, digest)

#ifdef __cplusplus
}
#endif
#endif
