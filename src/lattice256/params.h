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

//
// Can be used when the maximum number of inputs and outputs are 4.
// For larger values use params8.h or params16.h
//

#ifndef LACTXV2_PARAMS_H
#define LACTXV2_PARAMS_H

#define N       256
#define n       6
#define m       4
#define L       64
#define D       3

#define Q       17592186028033  // 2^44 - 2^14 + 1
#define Q2      8796093014016  // (2^44 - 2^14)/2
#define K1      44
#define K11     43
#define KMONT   46
#define K2      14
#define ROOT    25128005879
#define MONT    65532 // 2^46 \in [Q, 0]
#define QINV    57174873096193 // inverse_mod(Q, R)
#define FILTER  70368744177663
#define F1      16492691176449
#define F2      274877906944

#define GAMMA2  549755813888  // 2^39
#define GAMMA1  4294967296  // 2^32
#define ZAGG    GAMMA1
#define ALPHA   512  // 2^10
#define TAU     16  // 2^4
#define TAU1    128  // 2^7
#define TAU2    4294967296  // 2^32
#define TAU3    65536  // 2^16

#define GAMMA2_BITS  33
#define GAMMA1_BITS  32
#define ZAGG_BITS    28
#define ALPHA_BITS   9
#define TAU_BITS     4
#define TAU1_BITS    7
#define TAU2_BITS    32
#define TAU3_BITS    16

#define u_BYTES       ((K1 * N)/8)
#define z_BYTES       (L*((ALPHA_BITS + 1) * N)/8)
#define R_BYTES       ((m - D) * ((TAU2_BITS + 1) * N)/8)

#define r_BYTES       ((N)/8 * (TAU_BITS + 1))
#define r1_BYTES      ((N)/8 * (TAU1_BITS + 1))
#define r2_BYTES      ((N)/8 * (TAU2_BITS + 1))
#define r3_BYTES      ((N)/8 * (TAU3_BITS + 1))
#define a_BYTES       ((N)/8 * (ALPHA_BITS + 1))

#define BETA           60  // number of +1 or -1 in the challenge polynomial
#define SEED_BYTES     48
#define CRH_BYTES      64

#define u_ERROR        14
#define t1_ERROR       24
#define t2_ERROR       33
#define pk_ERROR       u_ERROR
#define y_ERROR        33
#define aggr_ERROR     33

#define CHI            64

#define u_HIGHBITS        ((((K11 - u_ERROR + 1) * N)/8) * n)
#define t1_HIGHBITS       ((((K11 - t1_ERROR + 1) * N)/8) * n)
#define t2_HIGHBITS       ((((K11 - t2_ERROR + 1) * N)/8) * n)
#define pk_HIGHBITS       ((((K11 - pk_ERROR + 1) * N)/8) * n)
#define y_HIGHBITS       ((((K11 - y_ERROR + 1) * N)/8) * n)

#define HINTBITS       2
#define HINTBYTES      ((((HINTBITS) * N)/8) * n)

#define MAX_ADDITIONS  15
#define MAX_ADDITIONS_BITS  3

#define UNIFORM_BLOCK ((768 + SHAKE128_RATE - 1)/SHAKE128_RATE)

// zeta_0 = (2^23 * root^(128)) mod q => 128 = bit_rev(0) index(1)
// zeta_1 = (2^23 * root^(129)) mod q => 129 = bit_rev(1) index()
// zeta_2 = (2^23 * root^(65)) mod q => 65 = bit_rev(2)
// 17592186044415 (index(0))
static const int64_t zetas[N] = {
        65532,    18605629968, -8503167997088,  1353408248862,
        6532059901091,  6270874789595,  7743964505125, -8683495166601,
        -7075184553544,  6467114370538,  6918871833738, -5791507952972,
        -8390273139442, -2161827015873, -7853471217573, -3071837438315,
        3590016244243, -5291137082928,  7628308115148,  8256041692546,
        1747823026676, -3385534370566, -2553935351067,  3553160446372,
        -7308928963971,  8214942054935,  8461079878170,   653749021754,
        867822013864, -2584305439064, -2950187113935, -6057207023439,
        -5600966724361, -6188950451958,  5329998310517, -8480018916594,
        -8076451537995, -6523493808586, -7961440074985, -4118303407856,
        -369534601629, -3572007986370, -1933455343990, -1684183259203,
        -5900594090629, -4323009812206,  -799395526122,  1185869469876,
        5922289129392,  8465296284866,  8105487554269, -1355025418203,
        -8686285105016,  2147915999642,  -378315691734, -2242578935165,
        4601190506722,  3890869737118,  -256108863701,  5697247006403,
        -5475660842263, -2272898399123, -4894320474582,  8188604734663,
        3892182687652,  7310148503740,    81181683295,  4925213270825,
        -1385504891341, -2345315422936, -7871855442902,  2521419268072,
        8003650120767,  4439906865357,   149532252000,  4273999063768,
        -1209996499728, -5193034442079,  4645012112624, -1933393325974,
        7283080935091,  2910704957524,    23104866765,  1493428022280,
        -4801166479099, -6693476858548, -3905013603701,  1431028714293,
        8199340500729, -2715757399078, -2598611589875,  2685919816105,
        -2442608857644,  2746617486736, -1322944093548, -1284296936110,
        -3874340694249,  7484809854103,  1859971576205,   453428212065,
        -7762297971391, -8499998453432,  -796868515394,   958704924890,
        5425405563489,  5526079022318, -3514762954984,  4031569601458,
        2868719430373,  7615626167513,  3641063162748,  -135275722959,
        6909915229321,  6217667253497,  8294526435406,   180752410475,
        -8365840272071, -1596287162939, -8219909069417, -4869334470179,
        2110865638948, -1977624777535,  2661123989348,  1043930913423,
        -3286087382736,  4320251224822,  -731910045614,  4153421577042,
        -6977005372474,  7977389628062, -7225942818867, -6467417767937,
        1801960745958,  6095206622265, -1683727970723, -8270784343472,
        -1820796191074,  8370521857400, -3437060465704,  5728355198772,
        -5698667667067, -4467995144684,  1104594818564, -1766577882133,
        -4601657143357,  4215715405021, -6613982453061,  -625623661339,
        -5741381774035,  3257795525470,  2735828156072,  4467189969663,
        6027274882700,  1056166321575, -6995376785108,  6136356850268,
        2151881977617, -5776686439715, -1743705770289,  2960768902248,
        -2419981704757,  2256230217155,  6610054882307,   943268943746,
        1816593236238, -1686354091870,  6383523770820,    51654753635,
        5613054071277,  4490773746593,  -136906849539, -1832744080361,
        4280850894713,   897593036418, -6026361701106, -6454246721093,
        -6891454815048, -5081908075606,  5984669618753, -8550043305036,
        3028572397129, -7701304604586,  -683230707109, -3387051632870,
        -6006196988898, -4897963070890, -8755726742615, -5351812503767,
        -4633928928938, -4129456541573,  3130998760012, -3514069935220,
        1112204927352, -6440584496901,  7182226780509, -3895686300352,
        8392896815257, -2792846269836, -8264986260935,  2785525032413,
        2043297751463,  1227538518038,  5952562937017, -3106700723813,
        7596081027376,  7727313088279,   -97908431538,  2726637791253,
        -8554992889132,  8722773742519,  4651195617871,  4876225273115,
        -7916557664429, -5271750415931,   826673737847, -6894085152553,
        -7685714897620,  1754395461461, -2569744671737,  4084162826751,
        -4342528684842,  2895972928744,   183245522388,   125775014364,
        2088336301792,  4468812828574, -3844116920144,  2215033377942,
        -2323781025965, -7760570204658,  2817723675801,  5131227148196,
        -7196094049714, -1810944263950,  5331353774625,  4149342795872,
        -2730408763017, -8427557371729,  5876157555160, -6326496167851,
        -8544274067304,  3395514969253,  3306171818146,  -171086047931,
        4037346696933,  1074048946736,  6499029095649, -8470212605533,
        -342329789085,  -872186652904,  6502903604911, -5867702705249,
        3709743750965,  3610523069659, -5560881826014,  1877993963009
};

#endif //LACTXV2_PARAMS_H
