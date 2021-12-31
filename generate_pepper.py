from Crypto.Random import get_random_bytes

if __name__ == '__main__':
    f = open('./application/pepper', 'wb')
    f.write(get_random_bytes(8))
    f.close()
