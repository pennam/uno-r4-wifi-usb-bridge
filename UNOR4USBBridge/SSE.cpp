/*
  This file is part of the UNOR4USBBridge project.

  Copyright (c) 2024 Arduino SA

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

/******************************************************************************
   INCLUDE
 ******************************************************************************/
#include <Arduino_DebugUtils.h>
#include <Preferences.h>

#include "mbedtls/pk.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

#include "mbedtls/error.h"
#include "mbedtls/asn1.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/sha256.h"

#include "SSE.h"

extern Preferences pref;

// New implementation from mbedtls not merged https://github.com/Mbed-TLS/mbedtls/pull/8703/files

/*
 * https://github.com/Mbed-TLS/mbedtls/blob/aa3fa98bc4a99d21a973b891bf7bda9a27647068/library/pk_wrap.c#L543
 * An ASN.1 encoded signature is a sequence of two ASN.1 integers. Parse one of
 * those integers and convert it to the fixed-length encoding expected by PSA.
 */
static int extract_ecdsa_sig_int(unsigned char **from, const unsigned char *end,
                                 unsigned char *to, size_t to_len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t unpadded_len, padding_len;

    if ((ret = mbedtls_asn1_get_tag(from, end, &unpadded_len,
                                    MBEDTLS_ASN1_INTEGER)) != 0) {
        return ret;
    }

    while (unpadded_len > 0 && **from == 0x00) {
        (*from)++;
        unpadded_len--;
    }

    if (unpadded_len > to_len || unpadded_len == 0) {
        return MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
    }

    padding_len = to_len - unpadded_len;
    memset(to, 0x00, padding_len);
    memcpy(to + padding_len, *from, unpadded_len);
    (*from) += unpadded_len;

    return 0;
}

/*
 * https://github.com/Mbed-TLS/mbedtls/blob/aa3fa98bc4a99d21a973b891bf7bda9a27647068/library/pk_wrap.c#L576
 * Convert a signature from an ASN.1 sequence of two integers
 * to a raw {r,s} buffer. Note: the provided sig buffer must be at least
 * twice as big as int_size.
 */
static int extract_ecdsa_sig(unsigned char **p, const unsigned char *end,
                             unsigned char *sig, size_t int_size)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t tmp_size;

    if ((ret = mbedtls_asn1_get_tag(p, end, &tmp_size,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        return ret;
    }

    /* Extract r */
    if ((ret = extract_ecdsa_sig_int(p, end, sig, int_size)) != 0) {
        return ret;
    }
    /* Extract s */
    if ((ret = extract_ecdsa_sig_int(p, end, sig + int_size, int_size)) != 0) {
        return ret;
    }

    return 0;
}

/*
 * https://github.com/Mbed-TLS/mbedtls/blob/47c74a477378ec3f0d1ba80547db836e078fa3a0/library/ecdsa.c#L609
 * Convert a signature (given by context) to ASN.1
 */
static int ecdsa_signature_to_asn1(const mbedtls_mpi *r, const mbedtls_mpi *s,
                                   unsigned char *sig, size_t sig_size,
                                   size_t *slen)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char buf[MBEDTLS_ECDSA_MAX_LEN] = { 0 };
    unsigned char *p = buf + sizeof(buf);
    size_t len = 0;

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&p, buf, s));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&p, buf, r));

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, buf,
                                                     MBEDTLS_ASN1_CONSTRUCTED |
                                                     MBEDTLS_ASN1_SEQUENCE));

    if (len > sig_size) {
        return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
    }

    memcpy(sig, p, len);
    *slen = len;

    return 0;
}


/******************************************************************************
   PUBLIC MEMBER FUNCTIONS
 ******************************************************************************/

int Arduino_UNOWIFIR4_SSE::generateECKeyPair(unsigned char* der, int maxLen)
{
  int ret = 1;
  mbedtls_pk_context key;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_entropy_context entropy;
  const char *pers = "gen_key";
  unsigned char tmp[128] = {0};

  mbedtls_pk_init(&key);
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen(pers))) != 0) {
    DEBUG_ERROR(" failed\n  ! mbedtls_ctr_drbg_seed returned -0x%04x\n", (unsigned int) -ret);
    goto exit;
  }

  if ((ret = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type((mbedtls_pk_type_t) MBEDTLS_PK_ECKEY))) != 0) {
    DEBUG_ERROR(" failed\n  !  mbedtls_pk_setup returned -0x%04x", (unsigned int) -ret);
    goto exit;
  }

  if ((ret = mbedtls_ecp_gen_key((mbedtls_ecp_group_id) MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(key), mbedtls_ctr_drbg_random, &ctr_drbg)) != 0) {
    DEBUG_ERROR(" failed\n  !  mbedtls_ecp_gen_key returned -0x%04x", (unsigned int) -ret);
    goto exit;
  }

  if ((ret = mbedtls_pk_write_key_der(&key, tmp, sizeof(tmp))) < 0) {
    DEBUG_ERROR(" failed\n  !  mbedtls_pk_write_key_der returned -0x%04x", (unsigned int) -ret);
    goto exit;
  }

  memcpy(der, &tmp[sizeof(tmp)- ret], ret);

exit:
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  mbedtls_pk_free(&key);

  return ret;
}

int Arduino_UNOWIFIR4_SSE::exportECKeyXY(const unsigned char* der, int len, uint8_t publicKey[])
{
  int ret = 1;
  mbedtls_pk_context key;
  mbedtls_ecp_keypair *ecp;

  mbedtls_pk_init(&key);

  /* Check if we can use parse public key */
  if ((ret = mbedtls_pk_parse_key(&key, der, len, NULL, 0)) != 0) {
    DEBUG_ERROR(" failed\n  !  mbedtls_pk_parse_key returned -0x%04x", (unsigned int) -ret);
    goto exit;
  }

  if (mbedtls_pk_get_type(&key) != MBEDTLS_PK_ECKEY) {
    DEBUG_ERROR(" failed\n  !  Not an EC KEY");
    goto exit;
  }

  /* Get elliptic curve point */
  ecp = mbedtls_pk_ec(key);
  mbedtls_mpi_write_binary(&ecp->Q.X, &publicKey[0],  32);
  mbedtls_mpi_write_binary(&ecp->Q.Y, &publicKey[32], 32);
  ret = 64;

exit:
  mbedtls_pk_free(&key);
  return ret;
}

int Arduino_UNOWIFIR4_SSE::importECKeyXY(uint8_t publicKey[], unsigned char* der, int len)
{
  int ret = 1;
  mbedtls_pk_context key;
  unsigned char tmp[128] = {0};
  mbedtls_ecp_keypair* ecp;

  mbedtls_pk_init(&key);

  if ((ret = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type((mbedtls_pk_type_t) MBEDTLS_PK_ECKEY))) != 0) {
    DEBUG_ERROR(" failed\n  !  mbedtls_pk_setup returned -0x%04x", (unsigned int) -ret);
    goto exit;
  }

  if (mbedtls_pk_get_type(&key) != MBEDTLS_PK_ECKEY) {
    DEBUG_ERROR(" failed\n  !  Not an EC KEY");
    goto exit;
  }

  ecp = mbedtls_pk_ec(key);

  if (( ret = mbedtls_ecp_group_load(&ecp->grp, MBEDTLS_ECP_DP_SECP256R1)) != 0) {
    DEBUG_ERROR(" failed\n  !  mbedtls_ecp_group_load returned -0x%04x", (unsigned int) -ret);
    goto exit;
  }

  tmp[0] = 0x04;
  memcpy(&tmp[1], publicKey, 64);

  if (( ret = mbedtls_ecp_point_read_binary(&ecp->grp, &ecp->Q, tmp, 65)) != 0) {
    DEBUG_ERROR(" failed\n  !  mbedtls_ecp_point_read_binary returned -0x%04x", (unsigned int) -ret);
    goto exit;
  }

  if ((ret = mbedtls_pk_write_pubkey_der(&key, tmp, sizeof(tmp))) < 0) {
    DEBUG_ERROR(" failed\n  !  mbedtls_pk_write_pubkey_der returned -0x%04x", (unsigned int) -ret);
    goto exit;
  }

  if (ret > len) {
    DEBUG_ERROR(" failed\n  !  outlen too small -0x%04x", (unsigned int) -ret);
    goto exit;
  }
  memcpy(der, &tmp[sizeof(tmp)- ret], ret);

exit:
  mbedtls_pk_free(&key);
  return ret;
}

int Arduino_UNOWIFIR4_SSE::sha256(const unsigned char* message, int len, unsigned char* sha256)
{
  int ret = 1;

  if((ret = mbedtls_sha256_ret(message, len, sha256, 0)) != 0) {
    DEBUG_ERROR(" failed\n  ! mbedtls_sha256_ret returned -0x%04x\n", (unsigned int) -ret);
    return ret;
  }
  return 32;
}

int Arduino_UNOWIFIR4_SSE::sign(const unsigned char* der, int len, const unsigned char* sha256, unsigned char* signature)
{
  int ret = 1;
  mbedtls_pk_context key;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_entropy_context entropy;
  unsigned char tmp[MBEDTLS_PK_SIGNATURE_MAX_SIZE] = {0};
  unsigned char * p = (unsigned char *)&tmp[0];
  const char *pers = "gen_key";

  mbedtls_pk_init(&key);
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen(pers))) != 0) {
    DEBUG_ERROR(" failed\n  ! mbedtls_ctr_drbg_seed returned -0x%04x\n", (unsigned int) -ret);
    goto exit;
  }

  /* verify if work using only private key*/
  if ((ret = mbedtls_pk_parse_key(&key, der, len, NULL, 0)) != 0) {
    DEBUG_ERROR(" failed\n  !  mbedtls_pk_parse_key returned -0x%04x", (unsigned int) -ret);
    goto exit;
  }

  size_t retSize;
  if ((ret = mbedtls_pk_sign(&key, MBEDTLS_MD_SHA256, sha256, 0, tmp, &retSize, mbedtls_ctr_drbg_random, &ctr_drbg)) != 0) {
    DEBUG_ERROR(" failed\n  !  mbedtls_pk_sign returned -0x%04x", (unsigned int) -ret);
    goto exit;
  }

#if SSE_DEBUG_ENABLED
  log_v("SSE::sign: der signature");
  log_buf_v(tmp, retSize);
#endif

  /* Extract {r,s} values from DER signature */
  extract_ecdsa_sig(&p, &tmp[retSize], signature, 32);
  ret = 64;

exit:
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_pk_free(&key);
  return ret;
}

int Arduino_UNOWIFIR4_SSE::verify(const unsigned char* der, int len, const unsigned char* sha256, unsigned char* signature)
{
  int ret = 1;
  mbedtls_pk_context key;
  unsigned char tmp[MBEDTLS_PK_SIGNATURE_MAX_SIZE] = {0};
  mbedtls_mpi r,s;
  size_t retSize = 0;

  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);
  mbedtls_pk_init(&key);

  /* Verify is only public key is needed */
  if ((ret = mbedtls_pk_parse_public_key(&key, der, len)) != 0) {
    DEBUG_ERROR(" failed\n  !  mbedtls_pk_parse_public_key returned -0x%04x", (unsigned int) -ret);
    goto exit;
  }

#if SSE_DEBUG_ENABLED
  log_v("SSE::verify: sha256");
  log_buf_v((const uint8_t *)sha256, 32);
  log_v("SSE::verify: compressed signature");
  log_buf_v((const uint8_t *)signature, 64);
#endif

  /* Convert signature {r,s} values to DER */
  mbedtls_mpi_read_binary( &r, signature, 32 );
  mbedtls_mpi_read_binary( &s, signature + 32, 32 );
  ecdsa_signature_to_asn1(&r, &s, tmp, MBEDTLS_PK_SIGNATURE_MAX_SIZE, &retSize);

#if SSE_DEBUG_ENABLED
  log_v("SSE::verify: der signature");
  log_buf_v((const uint8_t *)tmp, retSize);
#endif

  if ((ret = mbedtls_pk_verify(&key, MBEDTLS_MD_SHA256, sha256, 32, tmp, retSize)) != 0) {
    DEBUG_ERROR(" failed\n  !  mbedtls_pk_verify returned -0x%04x", (unsigned int) -ret);
    goto exit;
  }

exit:
  mbedtls_pk_free(&key);
  return ret;
}
