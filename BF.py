# =====================================================================
# Brute Force Attack on KE-DES  -  LIS4062 Information Security
# Homework No.3
# Ataque de fuerza bruta (known-plaintext) usando KE_DES.py
# =====================================================================

import time
import KE_DES

KEY_1 = '133457799BBCDFF1'
DATASET_1 = '0123456789ABCDEF'
DATASET_2 = '5544 4C41 5030 3236'.replace(' ', '')


# ---------------------------------------------------------------------
# Exhaustive Key Search (Brute Force)
# ---------------------------------------------------------------------

def brute_force(plain_hex, cipher_hex, fixed_bits):
    # El atacante conoce un par (plaintext, ciphertext) y prueba llaves.
    # fixed_bits = 56 bits (los de PC-1) que se dejan en ceros.
    # Solo se varian los 8 bits que usa la K-D (posiciones 8,16,...,64).
    plain = KE_DES.hex_to_bits(plain_hex, 64)
    cipher = KE_DES.hex_to_bits(cipher_hex, 64)
    found = []
    tested = 0
    start = time.perf_counter()
    for candidate in range(256):
        bits8 = format(candidate, '08b')
        # Se arma la llave de 64 bits: 7 bits de 'fixed_bits' + 1 bit del candidato
        key = ''
        for i in range(8):
            key = key + fixed_bits[i * 7:(i + 1) * 7] + bits8[i]
        subkeys = KE_DES.key_generation(key)
        result = KE_DES.ke_des_encryption(plain, subkeys, key)
        tested = tested + 1
        if result == cipher:
            found.append((key, bits8))
    elapsed = time.perf_counter() - start
    return found, tested, elapsed


# ---------------------------------------------------------------------
# Experimento 1: Brute force con Dataset 1
# ---------------------------------------------------------------------

def attack_experiment(name, plain_hex):
    print('=' * 78)
    print(name)
    print('=' * 78)
    # El "defensor" cifra con la llave secreta
    key = KE_DES.hex_to_bits(KEY_1, 64)
    subkeys = KE_DES.key_generation(key)
    cipher = KE_DES.ke_des_encryption(KE_DES.hex_to_bits(plain_hex, 64), subkeys, key)
    cipher_hex = KE_DES.bits_to_hex(cipher)
    print('  Secret key (unknown to attacker) :', KEY_1)
    print('  Known plaintext                  :', plain_hex)
    print('  Known ciphertext                 :', cipher_hex)
    print('  Search space tried               : 2^8 = 256 candidate keys')
    print()

    found, tested, elapsed = brute_force(plain_hex, cipher_hex, '0' * 56)
    print('  Keys tested        :', tested)
    print('  Matches found      :', len(found))
    for key_found, bits8 in found:
        print('  Candidate key      :', KE_DES.bits_to_hex(key_found))
        print('  8 effective bits   :', bits8, '(secret key bits:',
              ''.join([key[p - 1] for p in KE_DES.KD_KEY_BITS]) + ')')
    print('  Total time         : %.3f ms' % (elapsed * 1000))
    print('  Time per key       : %.1f microseconds' % (elapsed / tested * 1e6))
    print()
    return found, elapsed / tested


# ---------------------------------------------------------------------
# Verificacion con un segundo par (descartar falsos positivos)
# ---------------------------------------------------------------------

def second_pair_check(found):
    print('  Verification with a second plaintext/ciphertext pair (Dataset 2):')
    key_secret = KE_DES.hex_to_bits(KEY_1, 64)
    sub_secret = KE_DES.key_generation(key_secret)
    p2 = KE_DES.hex_to_bits(DATASET_2, 64)
    c2 = KE_DES.ke_des_encryption(p2, sub_secret, key_secret)
    for key_found, bits8 in found:
        sub = KE_DES.key_generation(key_found)
        r = KE_DES.ke_des_encryption(p2, sub, key_found)
        print('   candidate', KE_DES.bits_to_hex(key_found), '->', KE_DES.bits_to_hex(r),
              'expected', KE_DES.bits_to_hex(c2), ':', r == c2)
    print()


# ---------------------------------------------------------------------
# Estimacion del tiempo para el espacio de 64 bits (enfoque ingenuo)
# ---------------------------------------------------------------------

def time_estimate(per_key):
    print('=' * 78)
    print('TIME ESTIMATION (based on measured time per key)')
    print('=' * 78)
    seconds_per_year = 365 * 24 * 3600
    spaces = [('KE-DES effective key (8 bits)', 2 ** 8),
              ('DES key (56 bits)', 2 ** 56),
              ('KE-DES nominal key (64 bits)', 2 ** 64)]
    for label, size in spaces:
        total = size * per_key
        print('  %-30s keys = %.3e  time = %.3e s = %.3e years'
              % (label, size, total, total / seconds_per_year))
    print()


# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------

if __name__ == '__main__':
    f1, t1 = attack_experiment('BRUTE FORCE 1: Dataset 1 with Key 1', DATASET_1)
    second_pair_check(f1)
    f2, t2 = attack_experiment('BRUTE FORCE 2: Dataset 2 with Key 1', DATASET_2)
    time_estimate((t1 + t2) / 2)