#set page(numbering: "1")

#align(center, 
[= ASCipher Spedification])

== Introduction
ASCipher (Advanced Stream Cipher) is a standard stream encrytion algorithm, like any other stream ciphers, ASCipher obscures the cryptographic key and performs an `XOR` operation with the plaintext.

== Required parameters & Explaination
- Constant
- Counter
- Nonce
- Plaintext

In ASCipher, we used a lot of `XOR` operations. If we do encryption with a initial statement with almost 0 bits, the final confused bits will be likely filled with 0 bits. So we need to fill it with a pre-defined constant.

To avoid known plaintext attack, random sequence of each file has to be changed, `Nonce` is a random digit that guarantee the randomness of each file's random sequence.

== Pre-process
Before obscuring the key, we need to put the key, counter, nonece and the pre-defined constant into a 512-bit block.

#table(
    columns: (auto, auto, auto),
    [Offset], [Lenth], [Description],
    [0], [32], [Key],
    [32], [8], [Counter],
    [40], [8], [Nonce],
    [48], [16], [Constant]
)

Then put these 64 bytes into a 4x4 block with 32-bit unsigned integer, each integer follows big-endian.

The constant is defined as `0x72, 0x39, 0x97, 0x3f, 0x25, 0x2c, 0x19, 0xa6, 0x23, 0x0c, 0x5f, 0x04, 0xed, 0x92, 0x1a, 0x78`.

The counter has to be performed an `XOR` operation with a pre-defined constant `0x43a86711fcbcbd9`.

== Confuse Function
=== Definition
We define a confusion function `F` which takes 4 arguments ($A$, $B$, $C$ and $D$) and returns 4 arguments ($A_1$, $B_1$, $C_1$ and $D_1$):

$F(A, B, C, D) =$

$A_1 = (A xor B + 1) >> (C mod 32)$

$B_1 = (B + C xor 1) << (D mod 32)$

$C_1 = (C xor D - 1) >> (A mod 32)$

$D_1 = (D - A xor 1) << (B mod 32)$

Note that the shift right (>>) and shift left (<<) operations wrap the overflowed bits to the high or low positions respectively, unlike in typical programming languages.

=== Security
The confusion function is a typecal hash function, since we used module operation in our confusion function, one round of calculation can guarantee enough security, but to resist growing high hardware performance (for example ASIC or FPGA), we'll do this calculation for 20 rounds

== Confusing Process
A obscuring round contains these following steps, we need to do 20 rounds to ensure the random TOP is strong enough.

=== Step 1: Confuse rows
$M[1, 1], M[1, 2], M[1, 3], M[1, 4] = F(M[1, 1], M[1, 2], M[1, 3], M[1, 4])$

...

$M[4, 1], M[4, 2], M[4, 3], M[4, 4] = F(M[4, 1], M[4, 2], M[4, 3], M[4, 4])$

=== Step 2: Confuse columns
$M[1, 1], M[2, 1], M[3, 1], M[4, 1] = F(M[1, 1], M[2, 1], M[3, 1], M[4, 1])$

...

$M[4, 1], M[4, 2], M[4, 3], M[4, 4] = F(M[4, 1], M[4, 2], M[4, 3], M[4, 4])$

=== Step 3: Confuse from left top to right bottom
$M[1, 1], M[2, 2], M[3, 3], M[4, 4] = F(M[1, 1], M[2, 2], M[3, 3], M[4, 4])$

$M[1, 2], M[2, 3], M[3, 4], M[4, 1] = F(M[1, 2], M[2, 3], M[3, 4], M[4, 1])$

$M[1, 3], M[2, 4], M[3, 1], M[4, 2] = F(M[1, 3], M[2, 4], M[3, 1], M[4, 2])$

$M[1, 4], M[2, 1], M[3, 2], M[4, 3] = F(M[1, 4], M[2, 1], M[3, 2], M[4, 3])$

=== Step 4: Confuse from right top to left bottom
$M[1, 4], M[2, 3], M[3, 2], M[4, 1] = F([1, 4], M[2, 3], M[3, 2], M[4, 1])$

$M[1, 3], M[2, 2], M[3, 1], M[4, 4] = F(M[1, 3], M[2, 2], M[3, 1], M[4, 4])$

$M[1, 2], M[2, 1], M[3, 4], M[4, 3] = F(M[1, 2], M[2, 1], M[3, 4], M[4, 3])$

$M[1, 1], M[2, 4], M[3, 3], M[4, 2] = F(M[1, 1], M[2, 4], M[3, 3], M[4, 2])$

== Encryption & Decryption
Generate a series of predictable random blocks that the count of these blocks is equal to plaintext's.

Since we do `XOR` operation at encryption, the process of decryption is compeletely same as encryption.

== Extended Algorithms
=== ASCipher-hash-512
