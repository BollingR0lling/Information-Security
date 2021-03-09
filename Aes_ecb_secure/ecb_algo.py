import string
import random
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


def prepare(file_name):
    text_blocks = []
    padding_bytes = b'\x00' * 15
    result_dict = b''
    result_file = b''
    with open(file_name, 'rb') as file:
        file = [symbol for symbol in file.read()]
        for int_value in file:
            result_file += int_value.to_bytes(1, sys.byteorder) + padding_bytes
        for i in range(0, 256):
            result_dict += i.to_bytes(1, sys.byteorder) + padding_bytes
            text_blocks.append(i.to_bytes(1, sys.byteorder) + padding_bytes)

    with open(file_name, 'wb') as file:
        file.write(result_dict + result_file)

    with open('dictionary', 'wb') as dictionary:
        for dict_block in text_blocks:
            dictionary.write(dict_block)


def encode(key, prepared_file):
    BLOCK_SIZE = 16
    ciphered_text_blocks = []
    temp_str = b''
    aes = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    with open(prepared_file, 'rb') as file:
        data = file.read()
        for i in range(0, len(data)):
            if i % 16 == 0 and i != 0:
                encrypted_str = aes.encrypt(pad(temp_str, BLOCK_SIZE))
                ciphered_text_blocks.append(encrypted_str)
                temp_str = b''
            temp_str += data[i].to_bytes(1, sys.byteorder)
        encrypted_str = aes.encrypt(pad(temp_str, BLOCK_SIZE))
        ciphered_text_blocks.append(encrypted_str)

    with open(prepared_file, 'wb') as file:
        for ciphered_block in ciphered_text_blocks:
            file.write(ciphered_block)

    with open('dictionary', 'wb') as file:
        for i in range(256):
            file.write(ciphered_text_blocks[i])


def translate(file_name):
    decryption_dictionary = {}
    hex_block_size = 32
    padding_bytes = b'\x00' * 15

    with open('dictionary', 'rb') as file:
        symbol_list = file.read()
        temp_str = b''
        key = 0
        for i in range(len(symbol_list)):
            if i % hex_block_size == 0 and i != 0:
                decryption_dictionary[temp_str] = key.to_bytes(1, sys.byteorder) + padding_bytes
                key += 1
                temp_str = b''
            temp_str += symbol_list[i].to_bytes(1, sys.byteorder)
        decryption_dictionary[temp_str] = key.to_bytes(1, sys.byteorder) + padding_bytes

    with open(file_name, 'rb') as file:
        encrypted_text = file.read()
        encrypted_text_blocks = [
            encrypted_text[i:i + hex_block_size] for i in range(0, len(encrypted_text), hex_block_size)
        ]

        with open('translate', 'wb') as translate_table:
            for block in encrypted_text_blocks:
                translate_table.write(block + decryption_dictionary[block])


def decode(output_file):
    result_file = b''
    data_block_size = 32 + 16
    result_array = []
    with open('translate', 'rb') as file:
        table_array = file.read()
        with open(output_file, 'wb') as output:
            for i in range(0, len(table_array), data_block_size):
                cur_block = table_array[i:i + data_block_size]
                _, value = cur_block[:32], cur_block[32:]
                result_array.append(value)
            for element in result_array[256:]:
                first_byte = element[0]
                result_file += first_byte.to_bytes(1, sys.byteorder)
            output.write(result_file)


if __name__ == '__main__':
    command = sys.argv[1]
    if len(sys.argv) > 2:
        file_name = sys.argv[2]
        if command == 'prepare':
            prepare(file_name)
            print(f'File {file_name} is prepared, and dictionary was created')
        elif command == 'encode':
            rand_key = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(16))
            encode(rand_key, file_name)
            print(f'File {file_name} with dict is encoded with this random key: {rand_key}')
        elif command == 'translate':
            translate(file_name)
            print(f'Table created for {file_name}')
    elif command == 'decode':
        decode('output.jpg')
        print(f'File is decoded to output.jpg file')
