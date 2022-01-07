import string

class Config:

    @staticmethod
    def get_hashing_parameters():
        return {
            'time_const': 90,
            'hash_len': 32,
            'salt_len': 8
        }

    @staticmethod
    def get_accepted_characters():
        return string.ascii_letters + string.digits + string.punctuation
