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


#ifndef LACTX_PACK_H
#define LACTX_PACK_H

#include <stdint.h>
#include <string.h>
#include "params.h"
#include "lattice256/poly.h"

#define Q_BYTES       6   // should be able to reduce this even more

void pack_custom_poly(uint8_t *bytes, poly *a);
void unpack_custom_poly(poly *a, const uint8_t *bytes);

void pack_poly_ring_custom(uint8_t bytes[], poly_n *u, int p);
void unpack_poly_ring_custom(poly_n *u, const uint8_t bytes[], int p);

void pack_poly_ring(uint8_t bytes[LACTX_n * u_BYTES], poly_n *u);
void unpack_poly_ring(poly_n *u, const uint8_t bytes[LACTX_n * u_BYTES]);

void pack_poly_z(uint8_t bytes[z_BYTES], poly s[LACTX_L]);
void unpack_poly_z(poly s[LACTX_L], const uint8_t bytes[z_BYTES]);

void pack_poly_z_custom(uint8_t bytes[z_BYTES], poly s[LACTX_L], int bit_len);
void unpack_poly_z_custom(poly s[LACTX_L], const uint8_t bytes[z_BYTES], int bit_len);

void pack_poly_m_R(uint8_t bytes[r2_BYTES], poly s[LACTX_m - D]);
void unpack_poly_m_R(poly s[LACTX_m - D], const uint8_t bytes[LACTX_m * r2_BYTES]);

int get_sig_bytes(unsigned int in_len, unsigned int out_len);
void pack_poly_sig(uint8_t bytes[], poly s[LACTX_m - D], int additions);
void unpack_poly_sig(poly s[LACTX_m - D], uint8_t bytes[], int additions);

#endif //LACTX_PACK_H
