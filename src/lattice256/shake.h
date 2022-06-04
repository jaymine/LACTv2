/****************************************************************************
*    LACT+ - Post-Quantum Lattice-based Aggregable Transactions (Version 2) *
*    Copyright (C) 2022  Jayamine Alupotha                                  *
*                                                                           *
*    This program is free software: you can redistribute it and/or modify   *
*    it under the terms of the GNU General Public License as published by   *
*    the Free Software Foundation, either version 3 of the License, or      *
*    (at your option) any later version.                                    *
*                                                                           *
*    This program is distributed in the hope that it will be useful,        *
*    but WITHOUT ANY WARRANTY; without even the implied warranty of         *
*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          *
*    GNU General Public License for more details.                           *
*                                                                           *
*    You should have received a copy of the GNU General Public License      *
*    along with this program.  If not, see <https://www.gnu.org/licenses/>. *
*****************************************************************************/

#ifndef LACTx_SHAKE_H
#define LACTx_SHAKE_H

#include <stdint.h>
#include "fips202.h"
#include "params.h"

typedef keccak_state shake_state;

void shake128_stream_init(keccak_state *state, const uint8_t seed[SEED_BYTES], uint16_t nonce);

void shake256_stream_init(keccak_state *state, const uint8_t seed[CRH_BYTES], uint16_t nonce);

#endif //LACTx_SHAKE_H
