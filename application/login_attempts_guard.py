from datetime import datetime, timedelta

class LoginAttemptsGuard:

    def __init__(self):
        self.attempts = {}

    def refresh_login_attempts(self):
        for user in self.attempts.keys():
            moments = self.attempts[user]

            for moment in moments:
                if moment < datetime.now() - timedelta(minutes=30):
                    moments.remove(moment)

            if len(moments) == 0:
                self.attempts.pop(user)

    def add_login_attempt(self, username: str):
        if not username in self.attempts:
            self.attempts[username] = [datetime.now()]
        else:
            self.attempts[username].append(datetime.now())

    def verify_login_attempt(self, username: str):
        return not username in self.attempts or len(self.attempts[username]) < 3
