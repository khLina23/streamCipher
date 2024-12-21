import random

# Функция для генерации случайного ключа
def generate_key(length):

    return [random.randint(0, 255) for _ in range(length)]

# Функция для шифрования/дешифрования данных
def crypt_data(data, key, decrypt=False):

    result = []
    for i, byte in enumerate(data):
        if decrypt:

            result.append((byte - key[i % len(key)]) % 256)
        else:

            result.append((byte + key[i % len(key)]) % 256)
    return bytes(result)


def main():
    while True:
        print("\nВыберите действие:")
        print("1. Шифрование")
        print("2. Дешифрование")
        print("0. Выход")
        choice = input("Ваш выбор: ")

        try:
            if choice == '0':
                print("Выход из программы.")
                break
            elif choice == '1':
                plaintext = input("Введите текст для шифрования: ")
                plaintext_bytes = plaintext.encode('utf-8')
                key_length = len(plaintext_bytes)
                key = generate_key(key_length)
                print(f"Сгенерированный ключ (hex): {' '.join(hex(x)[2:] for x in key)}")
                ciphertext = crypt_data(plaintext_bytes, key)
                print(f"Зашифрованный текст (hex): {ciphertext.hex()}")
            elif choice == '2':
                ciphertext_hex = input("Введите зашифрованный текст (hex): ")
                ciphertext = bytes.fromhex(ciphertext_hex)
                key_hex = input("Введите ключ (hex, разделенный пробелами): ")
                key = [int(x, 16) for x in key_hex.split()]
                if len(key) != len(ciphertext):
                    print("Ошибка: длина ключа должна совпадать с длиной зашифрованного текста.")
                    continue
                decrypted_bytes = crypt_data(ciphertext, key, decrypt=True)
                decrypted_text = decrypted_bytes.decode('utf-8', errors='ignore')
                print(f"Расшифрованный текст: {decrypted_text}")
            else:
                print("Неверный выбор. Попробуйте снова.")
        except ValueError:
            print("Ошибка: Некорректный ввод данных. Проверьте формат ввода.")
        except Exception as e:
            print(f"Произошла ошибка: {e}")

if __name__ == "__main__":
    main()