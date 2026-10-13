import KE_DES

key = KE_DES.hex_to_bits('133457799BBCDFF1', 64)
subkeys = KE_DES.key_generation(key)

paper_K1 = '011011101010110000011010010000110001100110111101'
paper_K2 = '100100010101001111100101101111001110011001000010'

print('K1  ours :', subkeys[0])
print('K1  paper:', paper_K1)
print('K1  match:', subkeys[0] == paper_K1)
print('K2  ours :', subkeys[1])
print('K2  paper:', paper_K2)
print('K2  match:', subkeys[1] == paper_K2)
print('K15 == K1 :', subkeys[14] == subkeys[0])
print('K16 == K2 :', subkeys[15] == subkeys[1])