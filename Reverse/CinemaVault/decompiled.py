# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: cinema_vault.py
# Bytecode version: 3.12.0rc2 (3531)
# Source timestamp: 2025-05-16 23:41:48 UTC (1747438908)

import base64
import sys
import hashlib
import time

class CinemaVault:
    def __init__(self):
        self._QUOTES = ['dG8gaW5maW5pdHkgYW5kIGJleW9uZA==', 'aGVyZSdzIGxvb2tpbmcgYXQgeW91LCBraWQ=', 'aG91c3Rvbiwgd2UgaGF2ZSBhIHByb2JsZW0=', 'bWF5IHRoZSBmb3JjZSBiZSB3aXRoIHlvdQ==', 'bGlmZSBpcyBsaWtlIGEgYm94IG9mIGNob2NvbGF0ZXM=', 'c2F5IGhlbGxvIHRvIG15IGxpdHRsZSBmcmllbmQ=', 'aWxsIGJlIGJhY2s=', 'd2UncmUgZ29pbmcgdG8gbmVlZCBhIGJpZ2dlciBib2F0', 'eW91IHNoYWxsIG5vdCBwYXNz', 'aXRzIGFsaXZl']
        self._p_key = 'ClassicCinema'
        self._s_key = self._transform_key()
        self._scenes = {}
        self._initialize_scenes()
        self._vault_code = None

    def _transform_key(self):
        key = hashlib.sha256(self._p_key.encode()).digest()
        return base64.b64encode(key).decode()[:16]

    def _initialize_scenes(self):
        self._scenes = {'scene1': lambda x: self._xor_cipher(x, 0), 'scene2': lambda x: self._caesar_shift(x, 7), 'scene3': lambda x: self._reverse_string(x), 'scene4': lambda x: self._base64_decode(x), 'scene5': lambda x: self._substitution(x)}

    def _xor_cipher(self, text, idx):
        if idx >= len(self._QUOTES):
            return 'Invalid scene cut'
        decoded = base64.b64decode(self._QUOTES[idx]).decode()
        result = ''
        for i in range(len(decoded)):
            result += chr(ord(decoded[i]) ^ ord(self._s_key[i % len(self._s_key)]))
        return result

    def _caesar_shift(self, text, shift):
        if isinstance(text, bytes):
            text = text.decode()
        result = ''
        for char in text:
            if char.isalpha():
                ascii_offset = ord('a') if char.islower() else ord('A')
                result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
            else:  # inserted
                result += char
        return result

    def _reverse_string(self, text):
        if isinstance(text, bytes):
            text = text.decode()
        return text[::(-1)]

    def _base64_decode(self, text):
        try:
            if isinstance(text, str):
                text = text.encode()
            return base64.b64decode(text).decode()
        except:
            return 'Decoding error'

    def _substitution(self, text):
        if isinstance(text, bytes):
            text = text.decode()
        mapping = {'a': 'z', 'b': 'y', 'c': 'x', 'd': 'w', 'e': 'v', 'f': 'u', 'g': 't', 'h': 's', 'i': 'r', 'j': 'q', 'k': 'p', 'l': 'o', 'm': 'n', 'n': 'm', 'o': 'l', 'q': 'j', 'i': {'r': 'h', 's': 'g', 't': 'f', 'u': 'e', 'v': 'd', 'w': 'c', 'x': 'b', 'y': 'a', 'z': '
        result = ''
        for char in text.lower():
            result += mapping.get(char, char)
        return result

    def unlock_vault(self, code):
        if not code or len(code)!= 5:
            return 'Invalid code length! Must be 5 digits.'
        if not code.isdigit():
            return 'Code must contain only digits!'
        if not self._validate_vault_code(code):
            return 'Access denied! Incorrect vault code.'
        return self._get_vault_content()

    def _validate_vault_code(self, code):
        expected = self._generate_code()
        return code == expected

    def _generate_code(self):
        val = 12345
        val = val * 17 % 100000
        val = (val + 31415) % 100000
        val = (val ^ 42424) % 100000
        return str(val).zfill(5)

    def _get_vault_content(self):
        flag_parts = ['Q01De2MxN', 'HNzMWNfZ', 'jFsbXpf', 'YXJlX2', 'EwdF9', 'iQGNrfQ==']
        return ''.join(flag_parts)

    def analyze_quote(self, idx):
        if idx < 0 or idx >= len(self._QUOTES):
            return 'Quote index out of range'
        print(f'Analyzing quote {idx + 1}:')
        quote_encoded = self._QUOTES[idx]
        print(f'Encoded: {quote_encoded}')
        scene_results = []
        for scene_name, scene_func in self._scenes.items():
            try:
                result = scene_func(quote_encoded)
                scene_results.append(f'{scene_name}: {result}')
            except Exception as e:
                pass  # postinserted
        else:  # inserted
            return '\n'.join(scene_results)
            scene_results.append(f'{scene_name}: Error - {str(e)}')

    def challenge(self):
        print('🎬 Welcome to the Cinema Vault 🎬')
        print('A collection of the most iconic movie quotes of all time')
        print('----------------------------------------------------')
        print('1. Browse iconic movie quotes')
        print('2. Analyze a specific quote')
        print('3. Enter vault access code')
        print('4. Exit')
        while True:
            choice = input('\nSelect an option (1-4): ')
            if choice == '1':
                print('\nIconic Movie Quotes (encoded):')
                for i, quote in enumerate(self._QUOTES):
                    print(f'{i + 1}. {quote}')
            else:  # inserted
                if choice == '2':
                    try:
                        idx = int(input('Enter quote number (1-10): ')) - 1
                        print('\n' + self.analyze_quote(idx))
                else:  # inserted
                    if choice == '3':
                        code = input('Enter 5-digit vault access code: ')
                        result = self.unlock_vault(code)
                        print('\n' + result)
                    else:  # inserted
                        if choice == '4':
                            print('\nThank you for visiting the Cinema Vault. Until next time!')
                            sys.exit(0)
                        else:  # inserted
                            print('Invalid option. Please try again.')
        pass
if __name__ == '__main__':
    vault = CinemaVault()
    vault.challenge()