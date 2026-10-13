# =====================================================================
# Differential Cryptanalysis on KE-DES  -  LIS4062 Information Security
# Homework No.3
# =====================================================================

import random
import KE_DES

KEY_1 = '133457799BBCDFF1'


# ---------------------------------------------------------------------
# Difference Distribution Table (DDT) de una S-box
# ---------------------------------------------------------------------

def sbox_value(box, x):
    # x es un entero de 6 bits; devuelve la salida de 4 bits (entero)
    bits = format(x, '06b')
    row = int(bits[0] + bits[5], 2)
    column = int(bits[1:5], 2)
    return KE_DES.S_BOXES[box][row][column]


def make_ddt(box):
    # ddt[dx][dy] = cuantas entradas x cumplen S(x) xor S(x xor dx) = dy
    ddt = []
    for dx in range(64):
        ddt.append([0] * 16)
    for dx in range(64):
        for x in range(64):
            dy = sbox_value(box, x) ^ sbox_value(box, x ^ dx)
            ddt[dx][dy] = ddt[dx][dy] + 1
    return ddt


def best_of_ddt(ddt):
    # Mejor diferencial (dx != 0)
    best = 0
    best_dx = 0
    best_dy = 0
    for dx in range(1, 64):
        for dy in range(16):
            if ddt[dx][dy] > best:
                best = ddt[dx][dy]
                best_dx = dx
                best_dy = dy
    return best, best_dx, best_dy


def part1_ddt():
    print('=' * 78)
    print('[1] DIFFERENCE DISTRIBUTION TABLE (best differential of each S-box)')
    print('=' * 78)
    best_box = 0
    best_all = 0
    for box in range(8):
        ddt = make_ddt(box)
        best, dx, dy = best_of_ddt(ddt)
        print('  S%d: dx = %s -> dy = %s   count = %2d/64   p = %.4f'
              % (box + 1, format(dx, '06b'), format(dy, '04b'), best, best / 64))
    print()
    return


# ---------------------------------------------------------------------
# Efecto de la Key-Distribution Function (K-D) sobre las diferencias
# ---------------------------------------------------------------------

def part2_kd_differences():
    print('=' * 78)
    print('[2] DIFFERENCES THROUGH THE K-D FUNCTION')
    print('=' * 78)
    key = KE_DES.hex_to_bits(KEY_1, 64)
    subkeys = KE_DES.key_generation(key)
    R1 = ''.join([random.choice('01') for i in range(32)])
    R2 = ''.join([random.choice('01') for i in range(32)])
    e1 = KE_DES.key_distribution(R1, key, subkeys[0])
    e2 = KE_DES.key_distribution(R2, key, subkeys[0])
    d = KE_DES.xor(e1, e2)
    print('  Difference of R          :', KE_DES.group(KE_DES.xor(R1, R2), 8))
    print('  Difference after K-D (48):', KE_DES.group(d, 6))
    print('  S-box 1 input difference : %s  (always 000000: key bits only)' % d[0:6])
    print('  Last 8 bits difference   : %s  (always 00000000: subkey bits only)' % d[40:48])
    print()
    # Que S-boxes reciben siempre la misma entrada (independiente de los datos)
    print('  S-box | input depends on the data? (checked in all 16 rounds)')
    for box in range(8):
        constant = True
        for r in range(16):
            seen = []
            for t in range(50):
                R = ''.join([random.choice('01') for i in range(32)])
                x = KE_DES.xor(KE_DES.key_distribution(R, key, subkeys[r]), subkeys[r])
                seen.append(x[box * 6:box * 6 + 6])
            if len(set(seen)) != 1:
                constant = False
        if constant:
            print('  S%d    | NO  (constant input -> constant output)' % (box + 1))
        else:
            print('  S%d    | yes' % (box + 1))
    print()


# ---------------------------------------------------------------------
# Differential Characteristic (reduced rounds)
# ---------------------------------------------------------------------

def rounds_state(L, R, subkeys, key, n):
    # Aplica n rondas sobre (L, R) sin IP (IP es publica y no cambia el analisis)
    for i in range(n):
        L, R = KE_DES.single_round(L, R, subkeys[i], key)
    return L, R


def random_bits(n):
    return ''.join([random.choice('01') for i in range(n)])


def part3_characteristic():
    print('=' * 78)
    print('[3] DIFFERENTIAL CHARACTERISTIC ON REDUCED ROUNDS')
    print('=' * 78)
    key = KE_DES.hex_to_bits(KEY_1, 64)
    subkeys = KE_DES.key_generation(key)
    # Se busca la mejor S-box entre S3..S6 (reciben solo bits de R)
    best = 0
    box = 0
    dx = 0
    dy = 0
    for b in range(2, 6):
        c, x, y = best_of_ddt(make_ddt(b))
        if c > best:
            best, box, dx, dy = c, b, x, y
    p = best / 64
    print('  Chosen S-box: S%d  dx = %s  dy = %s  p = %d/64 = %.4f'
          % (box + 1, format(dx, '06b'), format(dy, '04b'), best, p))
    # dx -> diferencia en R (posiciones 6*box-8 ... en el vector de 48 bits)
    delta_R = ['0'] * 32
    bits_dx = format(dx, '06b')
    for j in range(6):
        delta_R[6 * box + j - 8] = bits_dx[j]
    delta_R = ''.join(delta_R)
    # dy -> diferencia a la salida de F (despues de P)
    pre_p = ['0'] * 32
    bits_dy = format(dy, '04b')
    for j in range(4):
        pre_p[4 * box + j] = bits_dy[j]
    delta_F = KE_DES.permutation(''.join(pre_p), KE_DES.P)
    print('  Delta R0 (X) :', KE_DES.bits_to_hex(delta_R))
    print('  Delta L0 (Y) :', KE_DES.bits_to_hex(delta_F))
    print('  Characteristic: (Y, X) -> (X, 0) -> (0, X) -> (X, Y)')
    print()
    N = 20000
    expected = {1: (delta_R, '0' * 32, p),
                2: ('0' * 32, delta_R, p),
                3: (delta_R, delta_F, p * p)}
    print('  Pairs per test:', N)
    print('  Rounds | predicted p | measured p | most frequent output diff (hex)')
    for n in [1, 2, 3, 4, 6, 8, 16]:
        counts = {}
        hits = 0
        for t in range(N):
            L = random_bits(32)
            R = random_bits(32)
            L2 = KE_DES.xor(L, delta_F)
            R2 = KE_DES.xor(R, delta_R)
            a = rounds_state(L, R, subkeys, key, n)
            b = rounds_state(L2, R2, subkeys, key, n)
            out = KE_DES.xor(a[0], b[0]) + KE_DES.xor(a[1], b[1])
            counts[out] = counts.get(out, 0) + 1
        top = max(counts, key=counts.get)
        if n in expected:
            predicted = '%.5f' % expected[n][2]
        else:
            predicted = '   -   '
        print('  %6d | %11s | %10.5f | %s'
              % (n, predicted, counts[top] / N, KE_DES.bits_to_hex(top)))
    print()


# ---------------------------------------------------------------------
# Avalanche effect
# ---------------------------------------------------------------------

def part4_avalanche():
    print('=' * 78)
    print('[4] AVALANCHE EFFECT (1 bit flipped in the plaintext)')
    print('=' * 78)
    key = KE_DES.hex_to_bits(KEY_1, 64)
    subkeys = KE_DES.key_generation(key)
    N = 500
    print('  Rounds | average bits changed (of 64)')
    for n in [1, 2, 3, 4, 6, 8, 12, 16]:
        total = 0
        for t in range(N):
            L = random_bits(32)
            R = random_bits(32)
            pos = random.randint(0, 63)
            both = L + R
            flipped = both[:pos] + ('1' if both[pos] == '0' else '0') + both[pos + 1:]
            a = rounds_state(L, R, subkeys, key, n)
            b = rounds_state(flipped[:32], flipped[32:], subkeys, key, n)
            diff = KE_DES.xor(a[0] + a[1], b[0] + b[1])
            total = total + diff.count('1')
        print('  %6d | %.2f' % (n, total / N))
    print()


if __name__ == '__main__':
    random.seed(2026)
    part1_ddt()
    part2_kd_differences()
    part3_characteristic()
    part4_avalanche()
