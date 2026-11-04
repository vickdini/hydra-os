import crypt
h = crypt.crypt('vick', crypt.mksalt(crypt.METHOD_SHA512))
print("Hash:", h)
print("Check:", crypt.crypt('vick', h) == h)

