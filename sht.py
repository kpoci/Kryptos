from argon2 import PasswordHasher
ph = PasswordHasher()
hash = ph.hash("karl")
hash
ph.verify(hash, "karl")