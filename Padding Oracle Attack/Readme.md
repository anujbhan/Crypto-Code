# The Padding Oracle Attack

It turns out that knowing whether or not a given ciphertext produces plaintext with
valid padding is ALL that an attacker needs to break a CBC encryption. If you can
feed in ciphertexts and somehow find out whether or not they decrypt to something 
with valid padding or not, then you can decrypt ANY given ciphertext.

So the only mistake that you need to make in your implementation of CBC encryption
is to have an API endpoint that returns 200 if the ciphertext gives a plaintext 
with valid padding, and 500 if not.

In my implementation, the attack is on a university server where a small piece of code
is intensionally exhibiting the above stated behaviour by sending "BAD_PAD" and "SUCCESS"
for invalid and valid padding respectively. Please go through the code for more details.
