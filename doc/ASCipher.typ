#align(center, 
[= ASCipher Spedification])

== Introduction
ASCipher (Advanced Stream Cipher) is a standard stream encrytion algorithm, like any other stream ciphers, ASCipher obscures the cryptographic key and performs an XOR operation with the plaintext.

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

Then put these 64 bytes into a 4x4 block with unsigned 32-bit integer.

== Confuse Function
We define a confusion function F which takes 4 arguments ($A$, $B$, $C$ and $D$) and returns 4 arguments ($A_1$, $B_1$, $C_1$ and $D_1$):

$F(A, B, C, D) =$

$A_1 = (A xor B + 1) >> (C mod 32)$

$B_1 = (B + C xor 1) << (D mod 32)$

$C_1 = (C xor D - 1) >> (A mod 32)$

$D_1 = (D - A xor 1) << (B mod 32)$

Note that the shift right (>>) and shift left (<<) operations wrap the overflowed bits to the high or low positions respectively, unlike in typical programming languages.

== Confusing Process
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


