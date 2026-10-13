# =====================================================================
# Linear Cryptanalysis on KE-DES  -  LIS4062 Information Security
# Homework No.3
# =====================================================================

import random
import KE_DES

KEY_1 = '133457799BBCDFF1'


# ---------------------------------------------------------------------
# Linear Approximation Table (LAT) de una S-box
# ---------------------------------------------------------------------

def sbox_value(box, x):
    bits = format(x, '06b')
    row = int(bits[0] + bits[5], 2)
    column = int(bits[1:5], 2)
    return KE_DES.S_BOXES[box][row][column]


def parity(x):
    # Paridad (XOR de todos los bits) de un entero
    return bin(x).count('1') % 2


def bias_count(box, alpha, beta):
    # Cuantas entradas x cumplen  alpha.x XOR beta.S(x) = 0, menos 32
    count = 0
    for x in range(64):
        y = sbox_value(box, x)
        if parity(alpha & x) ^ parity(beta & y) == 0:
            count = count + 1
    return count - 32


def best_linear(box):
    best = 0
    best_a = 0
    best_b = 0
    for alpha in range(1, 64):
        for beta in range(1, 16):
            b = bias_count(box, alpha, beta)
            if abs(b) > abs(best):
                best, best_a, best_b = b, alpha, beta
    return best, best_a, best_b


def part1_lat():
    print('=' * 78)
    print('[1] LINEAR APPROXIMATION TABLE (best approximation of each S-box)')
    print('=' * 78)
    for box in range(8):
        b, a, c = best_linear(box)
        print('  S%d: alpha = %s  beta = %s  count-32 = %+3d   bias = %+.4f'
              % (box + 1, format(a, '06b'), format(c, '04b'), b, b / 64))
    print()


# ---------------------------------------------------------------------
# One-round linear approximation measured on KE-DES
# ---------------------------------------------------------------------

def random_bits(n):
    return ''.join([random.choice('01') for i in range(n)])


def part2_one_round():
    print('=' * 78)
    print('[2] ONE-ROUND LINEAR APPROXIMATION (measured on KE-DES)')
    print('=' * 78)
    key = KE_DES.hex_to_bits(KEY_1, 64)
    subkeys = KE_DES.key_generation(key)
    # Se usa la mejor S-box entre S3..S6 (entradas solo de R)
    best = 0
    box = 0
    alpha = 0
    beta = 0
    for b in range(2, 6):
        v, a, c = best_linear(b)
        if abs(v) > abs(best):
            best, box, alpha, beta = v, b, a, c
    print('  Chosen S-box: S%d  alpha = %s  beta = %s  theoretical bias = %+.4f'
          % (box + 1, format(alpha, '06b'), format(beta, '04b'), best / 64))
    # Posiciones de R (0..31) que participan en la mascara de entrada
    alpha_bits = format(alpha, '06b')
    in_positions = []
    for j in range(6):
        if alpha_bits[j] == '1':
            in_positions.append(6 * box + j - 8)
    # Posiciones de F (despues de P) que participan en la mascara de salida
    beta_bits = format(beta, '04b')
    out_positions = []
    for j in range(4):
        if beta_bits[j] == '1':
            pre_p_position = 4 * box + j + 1
            out_positions.append(KE_DES.P.index(pre_p_position))
    print('  Approximation: XOR of R0 bits', in_positions,
          'and (L0 xor R1) bits', out_positions, ' = constant')
    N = 100000
    zeros = 0
    for t in range(N):
        L0 = random_bits(32)
        R0 = random_bits(32)
        L1, R1 = KE_DES.single_round(L0, R0, subkeys[0], key)
        v = 0
        for p in in_positions:
            v = v ^ int(R0[p])
        for p in out_positions:
            v = v ^ int(L0[p]) ^ int(R1[p])
        if v == 0:
            zeros = zeros + 1
    prob = zeros / N
    print('  Samples: %d   P(expression = 0) = %.4f   measured bias = %+.4f'
          % (N, prob, prob - 0.5))
    print()
    return abs(best) / 64


# ---------------------------------------------------------------------
# Piling-up lemma
# ---------------------------------------------------------------------

def part3_piling_up(eps):
    print('=' * 78)
    print('[3] PILING-UP LEMMA  (bias = 2^(n-1) * eps^n)')
    print('=' * 78)
    print('  Best single-round bias eps = %.4f' % eps)
    print('  n approximations | total bias   | data needed ~ 1/bias^2')
    for n in [1, 2, 3, 4, 6, 8, 12, 14, 16]:
        bias = (2 ** (n - 1)) * (eps ** n)
        print('  %16d | %.3e | %.3e' % (n, bias, 1 / (bias * bias)))
    print()
    print('  Known pairs available: 2^64 = %.3e' % (2.0 ** 64))
    print()


if __name__ == '__main__':
    random.seed(2026)
    part1_lat()
    eps = part2_one_round()
    part3_piling_up(eps)
