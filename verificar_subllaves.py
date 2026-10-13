# Verificacion: las subllaves K1-K16 dependen de la llave?
import KE_DES

key_a = KE_DES.hex_to_bits('133457799BBCDFF1', 64)
key_b = KE_DES.hex_to_bits('0E329232EA6D0D73', 64)
key_c = KE_DES.hex_to_bits('FFFFFFFFFFFFFFFF', 64)

sub_a = KE_DES.key_generation(key_a)
sub_b = KE_DES.key_generation(key_b)
sub_c = KE_DES.key_generation(key_c)

print('K1 (key A):', sub_a[0])
print('K1 (key B):', sub_b[0])
print('K1 (key C):', sub_c[0])
print('Subkeys A == B :', sub_a == sub_b)
print('Subkeys A == C :', sub_a == sub_c)

# Bits que usa PC-1 vs bits que usa la K-D
used_by_pc1 = []
for p in KE_DES.PC1:
    used_by_pc1.append(p)
print('Bits of the key used by PC-1 (56):', len(used_by_pc1))
print('Bits of the key used by K-D       :', KE_DES.KD_KEY_BITS)
print('Any K-D bit also in PC-1?         :', any(p in used_by_pc1 for p in KE_DES.KD_KEY_BITS))