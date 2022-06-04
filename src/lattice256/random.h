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


#ifndef LACTX_RANDOM_H
#define LACTX_RANDOM_H

#include <stdint.h>
#include <string.h>
#include "params.h"
#include "poly.h"

void get_value_mask(poly *a, uint8_t seed[a_BYTES], int64_t b);

void set_value_mask(poly *a, const uint8_t seed[a_BYTES]);

void get_custom_value_mask(poly *a, uint8_t seed[a_BYTES], int64_t b, int bit_len);

void set_custom_value_mask(poly *a, const uint8_t seed[a_BYTES], int bit_len);

void get_mask_tau(poly *a, uint8_t seed[r_BYTES]);

void get_mask_tau1(poly *a, uint8_t seed[r1_BYTES]);

void get_mask_tau2(poly *a, uint8_t seed[r2_BYTES]);

void get_mask_tau3(poly *a, uint8_t seed[r3_BYTES]);

void set_mask_tau(poly *a, const uint8_t seed[r_BYTES]);

void set_mask_tau1(poly *a, const uint8_t seed[r1_BYTES]);

void set_mask_tau2(poly *a, const uint8_t seed[r2_BYTES]);

void set_mask_tau3(poly *a, const uint8_t seed[r3_BYTES]);

#endif //LACTX_RANDOM_H
