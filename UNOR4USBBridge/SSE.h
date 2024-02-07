/*
  This file is part of the UNOR4USBBridge project.

  Copyright (c) 2024 Arduino SA

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

#ifndef ARDUINO_UNOWIFIR4_SSE_H_
#define ARDUINO_UNOWIFIR4_SSE_H_

/******************************************************************************
 * DEFINES
 ******************************************************************************/

#define SSE_DEBUG_ENABLED 0

/******************************************************************************
 * CLASS DECLARATION
 ******************************************************************************/

class Arduino_UNOWIFIR4_SSE
{

public:
  static int generateECKeyPair(unsigned char* der, int maxLen);
  static int exportECKeyXY(const unsigned char* der, int len, uint8_t publicKey[]);
  static int importECKeyXY(uint8_t publicKey[], unsigned char* der, int len);
  static int sign(const unsigned char* der, int len, const unsigned char* sha256, unsigned char* signature);
  static int verify(const unsigned char* der, int len, const unsigned char* sha256, unsigned char* signature);
  static int sha256(const unsigned char* message, int len, unsigned char* sha256);

};

#endif /* Arduino_UNOWIFIR4_SSE */
