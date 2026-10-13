# =====================================================================
# KE-DES (Key-based Enhanced DES)  -  LIS4062 Information Security
# Homework No.3
# Implementacion propia, sin librerias de criptografia.
# Los titulos de funciones/comentarios siguen las diapositivas del DES
# (Dr. Vicente Alarcon-Aquino) y el paper de Reyad et al. [2].
# Todos los bloques se manejan como cadenas de '0' y '1'.
# =====================================================================

import time

# ---------------------------------------------------------------------
# TABLES (tablas del paper, Fig. 2, Fig. 3, Table I y Table II)
# ---------------------------------------------------------------------

# Permuted Choice 1 (PC-1): 64 bits -> 56 bits
PC1 = [57, 49, 41, 33, 25, 17, 9,
       1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27,
       19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15,
       7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29,
       21, 13, 5, 28, 20, 12, 4]

# Permuted Choice 2 (PC-2): 56 bits -> 48 bits
PC2 = [14, 17, 11, 24, 1, 5,
       3, 28, 15, 6, 21, 10,
       23, 19, 12, 4, 26, 8,
       16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55,
       30, 40, 51, 45, 33, 48,
       44, 49, 39, 56, 34, 53,
       46, 42, 50, 36, 29, 32]

# Initial Permutation (IP)
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

# Inverse Initial Permutation (IP-1)
IP_INV = [40, 8, 48, 16, 56, 24, 64, 32,
          39, 7, 47, 15, 55, 23, 63, 31,
          38, 6, 46, 14, 54, 22, 62, 30,
          37, 5, 45, 13, 53, 21, 61, 29,
          36, 4, 44, 12, 52, 20, 60, 28,
          35, 3, 43, 11, 51, 19, 59, 27,
          34, 2, 42, 10, 50, 18, 58, 26,
          33, 1, 41, 9, 49, 17, 57, 25]

# Permutation Function (P)
P = [16, 7, 20, 21,
     29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2, 8, 24, 14,
     32, 27, 3, 9,
     19, 13, 30, 6,
     22, 11, 4, 25]

# Left Shift Box (Table I del paper)
LEFT_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# Key-Distribution Function (K-D), Fig. 1 del paper:
#   fila 1: 8 bits de la llave (posiciones 8,16,...,64) -> constantes en todas las rondas
#   filas 2-5: los 32 bits de R (posiciones 1..32)
#   fila 6: 8 bits de la subllave Ki (posiciones 9,18,27,36,15,22,29,4) -> cambian por ronda
KD_KEY_BITS = [8, 16, 24, 32, 40, 48, 56, 64]
KD_SUBKEY_BITS = [9, 18, 27, 36, 15, 22, 29, 4]

# Definition of S-boxes (S1 ... S8)
S_BOXES = [
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]],
]


# ---------------------------------------------------------------------
# Funciones auxiliares (conversion y operaciones sobre bits)
# ---------------------------------------------------------------------

def hex_to_bits(hex_string, n_bits):
    # Convierte hexadecimal a cadena de bits
    return format(int(hex_string, 16), '0' + str(n_bits) + 'b')


def bits_to_hex(bits):
    # Convierte cadena de bits a hexadecimal
    return format(int(bits, 2), '0' + str(len(bits) // 4) + 'X')


def permutation(bits, table):
    # Reordena los bits segun una tabla (posiciones empiezan en 1)
    result = ''
    for position in table:
        result = result + bits[position - 1]
    return result


def xor(a, b):
    # XOR bit a bit entre dos cadenas de igual longitud
    result = ''
    for i in range(len(a)):
        if a[i] == b[i]:
            result = result + '0'
        else:
            result = result + '1'
    return result


def left_shift(bits, n):
    # Left circular shift (rotacion a la izquierda) de n posiciones
    return bits[n:] + bits[:n]


def group(bits, size):
    # Separa los bits en grupos de 'size' bits (solo para imprimir)
    groups = []
    for i in range(0, len(bits), size):
        groups.append(bits[i:i + size])
    return ' '.join(groups)


# ---------------------------------------------------------------------
# Key Generation (KE-DES)
# ---------------------------------------------------------------------

# El paper (Table III y IV) muestra D0 = 1010..., pero el pseudocodigo del
# Odd/Even aplicado a 56 bits da D0 = 0101... Con True se reproducen las
# Tablas III y IV del paper (D0 invertido). Con False se sigue el pseudocodigo literal.
D0_AS_IN_PAPER_TABLE_III = True


def odd_even(bits):
    # Odd/Even Operation (Listing 1 del paper):
    # posicion par -> 1, posicion impar -> 0 (posiciones desde 1)
    result = ''
    for j in range(1, len(bits) + 1):
        if j % 2 == 0:
            result = result + '1'
        else:
            result = result + '0'
    return result


def key_generation(key64, show=False):
    # Key Generation / DES Key Schedule Calculation
    # 1) PC-1: 64 bits -> 56 bits
    after_pc1 = permutation(key64, PC1)
    # 2) Odd/Even sobre los 56 bits
    after_odd_even = odd_even(after_pc1)
    # 3) Split: C0 y D0 de 28 bits
    c = after_odd_even[:28]
    d = after_odd_even[28:]
    if D0_AS_IN_PAPER_TABLE_III:
        d = xor(d, '1' * 28)    # 0101... -> 1010...
    if show:
        print('  Key (64 bits)  :', group(key64, 8))
        print('  After PC-1     :', group(after_pc1, 8))
        print('  After Odd/Even :', group(after_odd_even, 8))
        print('  C0             :', c)
        print('  D0             :', d)
        print()
        print('  Round | Shifts | Ci                           | Di                           | Ki (48 bits)')
    subkeys = []
    for round_number in range(1, 17):
        # 4) Left Shift segun la tabla (Left Shift Box)
        shifts = LEFT_SHIFTS[round_number - 1]
        c = left_shift(c, shifts)
        d = left_shift(d, shifts)
        # 5) PC-2 sobre Ci||Di -> Ki de 48 bits
        k = permutation(c + d, PC2)
        subkeys.append(k)
        if show:
            print('  %5d | %6d | %s | %s | %s' % (round_number, shifts, c, d, k))
    return subkeys


# ---------------------------------------------------------------------
# Key-Distribution Function (K-D)  -  reemplaza a la Expansion Permutation (E)
# ---------------------------------------------------------------------

def key_distribution(R, key64, subkey):
    # Fila 1: 8 bits de la llave (constantes en todas las rondas)
    row1 = ''
    for position in KD_KEY_BITS:
        row1 = row1 + key64[position - 1]
    # Filas 2-5: los 32 bits de R
    rows2_5 = R
    # Fila 6: 8 bits de la subllave Ki (cambian en cada ronda)
    row6 = ''
    for position in KD_SUBKEY_BITS:
        row6 = row6 + subkey[position - 1]
    # Total: 8 + 32 + 8 = 48 bits
    return row1 + rows2_5 + row6


# ---------------------------------------------------------------------
# Definition of S-boxes
# ---------------------------------------------------------------------

def s_boxes(bits48):
    # 8 bloques de 6 bits -> 8 bloques de 4 bits (32 bits)
    result = ''
    for i in range(8):
        block = bits48[i * 6:(i + 1) * 6]
        row = int(block[0] + block[5], 2)    # primer y ultimo bit
        column = int(block[1:5], 2)          # 4 bits de en medio
        value = S_BOXES[i][row][column]
        result = result + format(value, '04b')
    return result


# ---------------------------------------------------------------------
# Calculation of F(R,K)
# ---------------------------------------------------------------------

def calculation_of_F(R, subkey, key64):
    expanded = key_distribution(R, key64, subkey)   # K-D (en vez de E)
    xored = xor(expanded, subkey)                   # XOR con Ki
    substituted = s_boxes(xored)                    # S-boxes
    return permutation(substituted, P)              # Permutation P


# ---------------------------------------------------------------------
# A DES Round / Single Round
# ---------------------------------------------------------------------

def single_round(L, R, subkey, key64):
    # Li = Ri-1 ;  Ri = Li-1 XOR F(Ri-1, Ki)
    new_L = R
    new_R = xor(L, calculation_of_F(R, subkey, key64))
    return new_L, new_R


# ---------------------------------------------------------------------
# KE-DES Encryption / Decryption (16 rounds)
# ---------------------------------------------------------------------

def ke_des_block(block64, subkeys, key64, show=False):
    # Initial Permutation (IP)
    after_ip = permutation(block64, IP)
    L = after_ip[:32]
    R = after_ip[32:]
    if show:
        print('  Input          :', bits_to_hex(block64))
        print('  After IP       :', bits_to_hex(after_ip))
        print('  L0 =', bits_to_hex(L), '  R0 =', bits_to_hex(R))
    # 16 rondas
    for i in range(16):
        L, R = single_round(L, R, subkeys[i], key64)
        if show:
            print('  Round %2d: L = %s  R = %s' % (i + 1, bits_to_hex(L), bits_to_hex(R)))
    # Swap final y Inverse Initial Permutation (IP-1)
    preoutput = R + L
    return permutation(preoutput, IP_INV)


def ke_des_encryption(plaintext64, subkeys, key64, show=False):
    return ke_des_block(plaintext64, subkeys, key64, show)


def ke_des_decryption(ciphertext64, subkeys, key64, show=False):
    # Mismo proceso pero con las subllaves en orden inverso (K16 ... K1)
    reversed_keys = []
    for i in range(15, -1, -1):
        reversed_keys.append(subkeys[i])
    return ke_des_block(ciphertext64, reversed_keys, key64, show)


# ---------------------------------------------------------------------
# Experimentos
# ---------------------------------------------------------------------

REPETITIONS = 10000   # repeticiones para promediar los tiempos


def run_experiment(name, plaintext_hex, key_hex, show_rounds=True):
    print('=' * 78)
    print(name)
    print('=' * 78)
    plaintext = hex_to_bits(plaintext_hex, 64)
    key = hex_to_bits(key_hex, 64)

    # --- Key generation + tiempo ---
    print('\n[1] KEY GENERATION')
    start = time.perf_counter()
    subkeys = key_generation(key)
    one_time = time.perf_counter() - start
    start = time.perf_counter()
    for i in range(REPETITIONS):
        key_generation(key)
    avg_time = (time.perf_counter() - start) / REPETITIONS
    key_generation(key, show=True)
    print('\n  Key generation time (1 run)        : %.1f microseconds' % (one_time * 1e6))
    print('  Key generation time (average of %d): %.2f microseconds' % (REPETITIONS, avg_time * 1e6))

    # --- Encryption ---
    print('\n[2] KE-DES ENCRYPTION')
    start = time.perf_counter()
    ciphertext = ke_des_encryption(plaintext, subkeys, key)
    enc_time = time.perf_counter() - start
    ke_des_encryption(plaintext, subkeys, key, show=show_rounds)
    print('  Plaintext  :', plaintext_hex.upper())
    print('  Ciphertext :', bits_to_hex(ciphertext))
    print('  Encryption time (1 run): %.1f microseconds' % (enc_time * 1e6))

    # --- Decryption ---
    print('\n[3] KE-DES DECRYPTION')
    start = time.perf_counter()
    recovered = ke_des_decryption(ciphertext, subkeys, key)
    dec_time = time.perf_counter() - start
    ke_des_decryption(ciphertext, subkeys, key, show=show_rounds)
    print('  Ciphertext :', bits_to_hex(ciphertext))
    print('  Recovered  :', bits_to_hex(recovered))
    print('  Decryption time (1 run): %.1f microseconds' % (dec_time * 1e6))
    if recovered == plaintext:
        print('  RESULT: decryption OK (recovered == original plaintext)')
    else:
        print('  RESULT: ERROR (does not match)')
    print()
    return ciphertext


# ---- DATOS DE ENTRADA (puedes cambiarlos) ----
KEY_1 = '133457799BBCDFF1'        # llave del ejemplo de la diapositiva 104
KEY_2 = '0E329232EA6D0D73'        # llave distinta, para comparar
DATASET_1 = '0123456789ABCDEF'    # mensaje del ejemplo de la diapositiva 105
DATASET_2 = '5544 4C41 5030 3236'.replace(' ', '')   # ASCII "UDLAP026"

if __name__ == '__main__':
    c1 = run_experiment('EXPERIMENT 1: Dataset 1 with Key 1', DATASET_1, KEY_1)
    c2 = run_experiment('EXPERIMENT 2: Dataset 2 with Key 1', DATASET_2, KEY_1)
    c3 = run_experiment('EXPERIMENT 3 (extra): Dataset 1 with Key 2', DATASET_1, KEY_2,
                        show_rounds=False)

    print('=' * 78)
    print('SUMMARY')
    print('=' * 78)
    print('  Dataset 1 + Key 1 ->', bits_to_hex(c1))
    print('  Dataset 2 + Key 1 ->', bits_to_hex(c2))
    print('  Dataset 1 + Key 2 ->', bits_to_hex(c3))
