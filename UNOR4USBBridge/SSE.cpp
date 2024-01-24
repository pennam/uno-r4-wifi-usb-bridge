/*
   This file is part of UNOR4USBBridge_SSE.

   Copyright 2023 ARDUINO SA (http://www.arduino.cc/)

   This software is released under the GNU General Public License version 3,
   which covers the main part of arduino-cli.
   The terms of this license can be found at:
   https://www.gnu.org/licenses/gpl-3.0.en.html

   You can be released from the requirements of the above licenses by purchasing
   a commercial license. Buying such a license is mandatory if you want to modify or
   otherwise use the software for commercial activities involving the Arduino
   software without disclosing the source code of your own applications. To purchase
   a commercial license, send an email to license@arduino.cc.
*/

/******************************************************************************
   INCLUDE
 ******************************************************************************/
#include <Arduino_DebugUtils.h>
#include <Preferences.h>

#include "mbedtls/pk.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

#include "SSE.h"

extern Preferences pref;

/******************************************************************************
   PUBLIC MEMBER FUNCTIONS
 ******************************************************************************/

int Arduino_UNOWIFIR4_SSE::generatePrivateKey(const char* keyID, uint8_t publicKey[])
{
  int ret = 1;
  int len = 0;
  mbedtls_pk_context key;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_entropy_context entropy;
  const char *pers = "gen_key";
  uint8_t der[1024] = {0};

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

  if (mbedtls_pk_get_type(&key) == MBEDTLS_PK_ECKEY) {
    mbedtls_ecp_keypair *ecp = mbedtls_pk_ec(key);
    mbedtls_mpi_write_binary(&ecp->Q.X, &publicKey[0],  32);
    mbedtls_mpi_write_binary(&ecp->Q.Y, &publicKey[32], 32);
  }
  
  if ((ret = mbedtls_pk_write_key_der(&key, der, sizeof(der))) < 0) {
    DEBUG_ERROR(" failed\n  !  mbedtls_pk_write_key_der returned -0x%04x", (unsigned int) -ret);
    goto exit;
  }

  if ((pref.begin("se")) != true) {
    DEBUG_ERROR(" failed\n  !  pref.begin returned false");
    goto exit;
  }

  len = ret;
  if ((ret = pref.putBytes(keyID, &der[sizeof(der) - ret], ret)) != len) {
    DEBUG_ERROR(" failed\n  !  pref.putBytes returned -0x%04x", (unsigned int) -ret);
    goto exit;
  }

  //log_buf_v(&der[sizeof(der) - ret], ret);

exit:
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  mbedtls_pk_free(&key);
  pref.end();

  if (ret == len) {
    return 64;
  }
  return 0;
}

int Arduino_UNOWIFIR4_SSE::generatePublicKey(const char* keyID, uint8_t publicKey[])
{
  int ret = 1;
  mbedtls_pk_context key;
  uint8_t der[1024] = {0};

  if ((pref.begin("se")) != true) {
    DEBUG_ERROR(" failed\n  !  pref.begin returned false");
    goto exit;
  }

  if ((ret = pref.getBytes(keyID, der, sizeof(der))) < 64) {
    DEBUG_ERROR(" failed\n  !  pref.getBytes returned -0x%04x", (unsigned int) -ret);
    goto exit;
  }

  //log_buf_v(der, ret);

  mbedtls_pk_init(&key);

  if ((ret = mbedtls_pk_parse_key(&key, (const unsigned char*)der, ret, NULL, 0)) != 0) {
    DEBUG_ERROR(" failed\n  !  mbedtls_pk_parse_key returned -0x%04x", (unsigned int) -ret);
    goto exit;
  }

  if (mbedtls_pk_get_type(&key) == MBEDTLS_PK_ECKEY) {
    mbedtls_ecp_keypair *ecp = mbedtls_pk_ec(key);
    mbedtls_mpi_write_binary(&ecp->Q.X, &publicKey[0],  32);
    mbedtls_mpi_write_binary(&ecp->Q.Y, &publicKey[32], 32);
  }

exit:
  mbedtls_pk_free(&key);
  pref.end();

  return 64;
}

