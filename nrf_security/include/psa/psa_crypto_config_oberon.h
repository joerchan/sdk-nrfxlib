/*
 * Copyright (c) 2021 Nordic Semiconductor
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#if defined(PSA_CRYPTO_DRIVER_HAS_CIPHER_SUPPORT_OBERON)
#define PSA_NEED_OBERON_CIPHER_DRIVER                         1
#define PSA_NEED_OBERON_CHACHA20                              1
#endif

#if defined(PSA_CRYPTO_DRIVER_HAS_AEAD_SUPPORT_OBERON)
#define PSA_NEED_OBERON_AEAD_DRIVER                           1
#endif

#if defined(PSA_CRYPTO_DRIVER_HAS_HASH_SUPPORT_OBERON)
#define PSA_NEED_OBERON_HASH_DRIVER                           1
#endif

#if defined(PSA_CRYPTO_DRIVER_HAS_ASYM_SIGN_SUPPORT_OBERON)
#define PSA_NEED_OBERON_ASYM_SIGN_SUPPORT                     1
#endif

#if defined(PSA_CRYPTO_DRIVER_HAS_ECC_SUPPORT_OBERON)
#define PSA_NEED_OBERON_ECC_SUPPORT                           1
#endif

#if defined(PSA_CRYPTO_DRIVER_HAS_ACCEL_KEY_TYPES_OBERON)
#define PSA_NEED_OBERON_ACCEL_KEY_TYPES                       1
#endif

#if defined(PSA_CRYPTO_DRIVER_ALG_CBC_NO_PADDING_OBERON)
#define PSA_NEED_OBERON_AES_CBC_NO_PADDING                    1
#endif

#if defined(PSA_CRYPTO_DRIVER_ALG_CBC_PKCS7_OBERON)
#define PSA_NEED_OBERON_AES_CBC_PKCS7                         1
#endif

#if defined(PSA_CRYPTO_DRIVER_ALG_CCM_OBERON)
#define PSA_NEED_OBERON_AES_CCM                               1
#endif

#if defined(PSA_CRYPTO_DRIVER_ALG_CMAC_OBERON)
#define PSA_NEED_OBERON_CMAC                                  1
#endif

#if defined(PSA_CRYPTO_DRIVER_ALG_CHACHA20_POLY1305_OBERON)
#define PSA_NEED_OBERON_CHACHA20_POLY1305                     1
#endif

#if defined(PSA_CRYPTO_DRIVER_ALG_CMAC_OBERON)
#define PSA_NEED_OBERON_CMAC                                  1
#endif

#if defined(PSA_CRYPTO_DRIVER_ALG_CTR_OBERON)
#define PSA_NEED_OBERON_AES_CTR                               1
#endif

#if defined(PSA_CRYPTO_DRIVER_ALG_DETERMINISTIC_ECDSA_OBERON)
#define PSA_NEED_OBERON_DETERMINISTIC_ECDSA                   1
#endif

#if defined(PSA_CRYPTO_DRIVER_ALG_ECB_NO_PADDING_OBERON)
#define PSA_NEED_OBERON_AES_ECB_NO_PADDING                    1
#endif

#if defined(PSA_CRYPTO_DRIVER_ALG_ECDH_OBERON)
#define PSA_NEED_OBERON_ECDH_DRIVER                           1
#define PSA_NEED_OBERON_ECDH_P224                             1
#define PSA_NEED_OBERON_ECDH_P256                             1
#define PSA_NEED_OBERON_ECDH_P384                             1
#define PSA_NEED_OBERON_ECDH_X25519                           1
#endif

#if defined(PSA_CRYPTO_DRIVER_ALG_ECDSA_OBERON)
#define PSA_NEED_OBERON_ECDSA_DRIVER                          1
#define PSA_NEED_OBERON_ECDSA_P224                            1
#define PSA_NEED_OBERON_ECDSA_P256                            1
#define PSA_NEED_OBERON_ECDSA_P384                            1
#define PSA_NEED_OBERON_ECDSA_ED25519                         1
#define PSA_NEED_OBERON_DETERMINISTIC_ECDSA                   1
#define PSA_NEED_OBERON_RANDOMIZED_ECDSA                      1
#endif

#if defined(PSA_CRYPTO_DRIVER_ALG_GCM_OBERON)
#define PSA_NEED_OBERON_AES_GCM                               1
#endif

#if defined(PSA_CRYPTO_DRIVER_ALG_HKDF_OBERON)
#define PSA_NEED_OBERON_KDF_DRIVER                            1
#define PSA_NEED_OBERON_HKDF                                  1
#define PSA_NEED_OBERON_HKDF_EXTRACT                          1
#define PSA_NEED_OBERON_HKDF_EXPAND                           1
#endif

#if defined(PSA_CRYPTO_DRIVER_ALG_HMAC_OBERON)
#define PSA_NEED_OBERON_HMAC                                  1
#endif

#if defined(PSA_CRYPTO_DRIVER_ALG_SHA_1_OBERON)
#define PSA_NEED_OBERON_SHA_1                                 1
#endif

#if defined(PSA_CRYPTO_DRIVER_ALG_SHA_224_OBERON)
#define PSA_NEED_OBERON_SHA_224                               1
#endif

#if defined(PSA_CRYPTO_DRIVER_ALG_SHA_256_OBERON)
#define PSA_NEED_OBERON_SHA_256                               1
#endif

#if defined(PSA_CRYPTO_DRIVER_ALG_SHA_384_OBERON)
#define PSA_NEED_OBERON_SHA_384                               1
#endif

#if defined(PSA_CRYPTO_DRIVER_ALG_SHA_512_OBERON)
#define PSA_NEED_OBERON_SHA_512                               1
#endif

#if defined(PSA_CRYPTO_DRIVER_ECC_SECP_R1_224_OBERON)
#define PSA_NEED_OBERON_KEY_PAIR_DRIVER                       1
#define PSA_NEED_OBERON_KEY_PAIR_P224                         1
#define PSA_NEED_OBERON_KEY_PAIR_SECP                         1
#endif

#if defined(PSA_CRYPTO_DRIVER_ECC_SECP_R1_256_OBERON)
#define PSA_NEED_OBERON_KEY_PAIR_DRIVER                       1
#define PSA_NEED_OBERON_KEY_PAIR_P256                         1
#define PSA_NEED_OBERON_KEY_PAIR_SECP                         1
#endif

#if defined(PSA_CRYPTO_DRIVER_ECC_MONTGOMERY_255_OBERON)
#define PSA_NEED_OBERON_KEY_PAIR_DRIVER                       1
#define PSA_NEED_OBERON_KEY_PAIR_X25519                       1
#define PSA_NEED_OBERON_KEY_PAIR_25519                        1
#endif

#if defined(PSA_CRYPTO_DRIVER_ECC_TWISTED_EDWARDS_255_OBERON)
#define PSA_NEED_OBERON_KEY_PAIR_DRIVER                       1
#define PSA_NEED_OBERON_KEY_PAIR_ED25519                      1
#endif