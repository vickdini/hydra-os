import crypt
h = crypt.crypt('hydra', crypt.mksalt(crypt.METHOD_SHA512))
print("Hash:", h)
print("Check:", crypt.crypt('hydra', h) == h)

