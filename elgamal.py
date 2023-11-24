import click
import random
from termcolor import colored
from sympy import mod_inverse

def generate_key(p):
    private_key = random.randint(2, p - 2)
    public_key = pow(g, private_key, p)
    return public_key, private_key

def encrypt_block(block, public_key, p):
    k = random.randint(2, p - 2)
    c1 = pow(g, k, p)
    c2 = (block * pow(public_key, k, p)) % p
    return c1, c2

def decrypt_block(c1, c2, private_key, p):
    s = pow(c1, private_key, p)
    s_inverse = mod_inverse(s, p)
    decrypted_block = (c2 * s_inverse) % p
    return decrypted_block

def encrypt(message, public_key, p):
    ciphertext = b''
    for i in range(0, len(message), BLOCK_SIZE):
        block = int.from_bytes(message[i:i + BLOCK_SIZE], 'big')
        c1, c2 = encrypt_block(block, public_key, p)
        ciphertext += c1.to_bytes(BLOCK_SIZE, 'big') + c2.to_bytes(BLOCK_SIZE, 'big')
    return ciphertext

def decrypt(ciphertext, private_key, p):
    plaintext = b''
    for i in range(0, len(ciphertext), 2 * BLOCK_SIZE):
        c1 = int.from_bytes(ciphertext[i:i + BLOCK_SIZE], 'big')
        c2 = int.from_bytes(ciphertext[i + BLOCK_SIZE:i + 2 * BLOCK_SIZE], 'big')
        decrypted_block = decrypt_block(c1, c2, private_key, p)
        plaintext += decrypted_block.to_bytes(BLOCK_SIZE, 'big')
    return plaintext

@click.command()
def main():
    # Your ElGamal parameters (p and g should be public)
    p = 23
    global g
    g = 5

    # Other parameters
    global BLOCK_SIZE
    BLOCK_SIZE = 2

    # Generate key pair
    public_key, private_key = generate_key(p)

    # Input message
    plaintext = click.prompt('Enter Plain Text (in ASCII): ', default='Hello World!')

    # Encryption
    ciphertext = encrypt(plaintext.encode('utf-8'), public_key, p)

    # Display ciphertext components
    click.echo(f'\nCiphertext: {colored(ciphertext.hex(), "green")}')

    # Decryption
    decrypted_text = decrypt(ciphertext, private_key, p)

    # Display the decrypted message
    click.echo(f'Decrypted Text: {colored(decrypted_text.decode("utf-8"), "green")}')


if __name__ == '__main__':
    main()
