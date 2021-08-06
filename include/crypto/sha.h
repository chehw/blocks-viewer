#ifndef CRYPTO_SHA_H_
#define CRYPTO_SHA_H_

#include <stdio.h>
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <gnutls/crypto.h>

#define sha_hash(algorithm, msg, cb_msg, digest) gnutls_hash_fast(algorithm, msg, cb_msg, digest)
#define sha256_hash(msg, cb_msg, digest) sha_hash(GNUTLS_DIG_SHA256, msg, cb_msg, digest)
#define sha512_hash(msg, cb_msg, digest)   sha_hash(GNUTLS_DIG_SHA512, msg, cb_msg, digest)
#define ripemd160_hash(msg, cb_msg, digest) sha_hash(GNUTLS_DIG_RMD160, msg, cb_msg, digest)

typedef struct hash_ctx 
{
	gnutls_hash_hd_t handle;
}sha_ctx_t, sha256_ctx_t, sha512_ctx_t, ripemd160_ctx_t;

#define sha_init(ctx, algorithm) gnutls_hash_init(&(ctx)->handle, algorithm)
#define sha_update(ctx, msg, cb_msg) gnutls_hash(ctx->handle, msg, cb_msg)
#define sha_final(ctx, digest) gnutls_hash_deinit(ctx->handle, digest)


#define sha1_init(ctx)   sha_init(ctx, GNUTLS_DIG_SHA1)
#define sha224_init(ctx) sha_init(ctx, GNUTLS_DIG_SHA224)
#define sha256_init(ctx) sha_init(ctx, GNUTLS_DIG_SHA256)
#define sha384_init(ctx) sha_init(ctx, GNUTLS_DIG_SHA384)
#define sha512_init(ctx) sha_init(ctx, GNUTLS_DIG_SHA512)
#define ripemd_init(ctx) sha_init(ctx, GNUTLS_DIG_RMD160)

#define sha1_update(ctx, msg, cb_msg)   sha_update(ctx, msg, cb_msg);
#define sha224_update(ctx, msg, cb_msg) sha_update(ctx, msg, cb_msg)
#define sha256_update(ctx, msg, cb_msg) sha_update(ctx, msg, cb_msg)
#define sha384_update(ctx, msg, cb_msg) sha_update(ctx, msg, cb_msg)
#define sha512_update(ctx, msg, cb_msg) sha_update(ctx, msg, cb_msg)
#define ripemd_update(ctx, msg, cb_msg) sha_update(ctx, msg, cb_msg)


#define sha1_final(ctx, digest)   sha_final(ctx, digest)
#define sha224_final(ctx, digest) sha_final(ctx, digest)
#define sha256_final(ctx, digest) sha_final(ctx, digest)
#define sha384_final(ctx, digest) sha_final(ctx, digest)
#define sha512_final(ctx, digest) sha_final(ctx, digest)
#define ripemd_final(ctx, digest) sha_final(ctx, digest)

#ifdef __cplusplus
}
#endif
#endif
