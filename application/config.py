class Config:

    @staticmethod
    def get_hashing_parameters():
        return {
            'time_const': 30,
            'hash_len': 32,
            'salt_len': 8
        }
