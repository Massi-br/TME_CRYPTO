# SDSA forge (nonce réutilisé)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from pyasn1.type import univ
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.codec.der.decoder import decode as der_decode
import hashlib
"""
Avec l'appui des 2 mails récupérés ainsi que la clée publique de Madame Ménissier-Morain,
La vulnérabilité introduite par "BuggyMailClient" est la réutilisation de la même nonce k
Notre objectif est de récupérer la clée privée x ainsi que la nonce k, afin de signer n'importe
quel challenge en se faisant passer pour Valérie. ;)

Explication mathématique:

Tirer un nonce k,
r = g**k mod p
c = H(m || r) mod q
s = k + c*x mod q
Signature -> (c,s)

Si deux signatures (c1,s1), (c2,s2) sont faites avec le même k, on a :

s1 = k+c1*x mod q et  s2 = k+c2*x mod q

on soustrait s1 par s2:

s1-s2 = (c1, s1)x (modq) => x = (s1,s2)(c1-c2)**-1 (mod q)
HORS on connait s1,s2 et nous pouvons aisément extraire c1 et c2 de leurs challenges respectifs
nous avons juste a calculer simplement x

et nous pouvons déduire k = s1-c1*x (mod q)

On connait x secret ainsi que k, NOUS POUVONS DONC SIGNER UN CHALLENGE EN SE FAISANT PASSER POUR
VALERIE

"""


#Pubkey de valérie
PUBKEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MIIDSDCCAjoGByqGSM44BAEwggItAoIBAQD+TrmX70MlK5VQTB/3ByHaipCp6N5C
QKT5+WOXcPIgXU0+f3rdj6TvflvYZOaaQj53oVQDOg4FEbc8y7mfYz7LoAGFbXnv
ylxjbRjLAvCnw4NfqaFPuOLjV+k948OkjcnqGkeNG6+XSxDZgNjXYs+55+PD7nsX
ARLdwL/k7hKfY8bt2bLw77GX+A6LBIOCzxPqdV1vSwO5tFiLBjXyjo26A00RuKI1
xX4Be+nSdt8U+2dCs55Tzvq1Zm10CKCMCiJ4BFObgHP6G7JVuXHwsxbyhHWaF0a4
01e1ITsJeI1lDoYGkrFlNSQCUdxeo1Gkz2N+3JQm0cPlgRDmJXHiSDjNAiEA7/BY
XCmA8Ng8RKfqXZh/Ds0BeDYPI3Bhgs0wpIbOqYsCggEBAJcQdO866MgpH9yOI09s
yAKqTA5K3Qv5hyGJVq1QasYYabHvdI4zCmCrro2evIrU5FMAiBLMeSnlA0QCGhD7
EkU92GN/gfJ7bYSkTxEN/KCT1nlcBJpWyRDZBcbBJmKGZjPo0QIDQ+Y9JjJsGclk
9ZtjGVrXLDq3g/QQU304KXxiFs7GyC+0sunCLDMfjXY8vsOwAC0MgNenGdsIT2io
iRRTFXnVne47EMVt9y8MswMl1Sv9aKyGjYhN47a9z2uZC4y4RVVU1s/vymLG424G
W6Y7z5mDO33HdO/Rr+yCYjbX+2Vn1MHpNfO5gfFzu6ya7lbKM936JdgCKXTMFpIK
Z6sDggEGAAKCAQEAjRSfsUguof82L93NVyyLeI9YFfo0+g5yH5FlI+Hvr0tnDOh+
9H6LGGtPoBxvcO1d4t1nO7DBdKufNbTFdP/dtg1Kv//FrJG7IcTOExtavhAZ9Gsg
Um8x0ysRp4KtRl9RUMdgklhZr2Hwqj9MvkemRKLBCZw8RDDFYAzS8csVmDOuMFN3
mYg/+wZDFAwxBJf0LFKV5+GPJXSpFEBkqpE68xe1tTKHqZ96JpDaLESEYBCmUGjA
OEyYub77kWNaCTf3KCn/L2XLl2ovPcLmCxXPccCTKkgU+uJWS74wE5K5FmgBaWOz
EghTqNWxqQVwLZrKLtyfsPUJw/tlklYnABw9Tg==
-----END PUBLIC KEY-----"""


# Signatures en héxa, récupérées depuis header X-Signature des mails trouvés
SIG1_HEX = "3044022059D8C3B0B6EE6641B456E60F5AEBD5878192005A3860CF02C4057D3ABA4331A302204047D88E1B6BF26A3CCB53C4C7AE7C2CE11DB982101DAE1C122F63D4825D691A"
SIG2_HEX = "304402204C82D5E9F158F087D10C87532A14BA05417C14929274EA586B8142F2CE925288022032260C18C53E07AA0D097F788214A5D38A62D5F5E6B77618AA4425EFADEF1335"


# Convertit une signature DER (représentée en hexadécimal) en couple (c, s)
def der_to_cs(hexsig):
    seq, _ = der_decode(bytes.fromhex(hexsig), asn1Spec=univ.Sequence())
    return int(seq[0]), int(seq[1])
# Encode le couple (c, s) en signature DER (octets).
def cs_to_der(c, s):
    seq = univ.Sequence()
    seq.setComponentByPosition(0, univ.Integer(c))
    seq.setComponentByPosition(1, univ.Integer(s))
    return der_encode(seq)
# Extrait (p, q, g) d'une clé publique DSA en PEM.
def load_dsa_params(pem):
    pub = serialization.load_pem_public_key(pem, backend=default_backend())
    nums = pub.public_numbers().parameter_numbers
    return nums.p, nums.q, nums.g
# Récupère la clé secrète x et le nonce k quand le même k a été réutilisé.
def recover_x_k(c1, s1, c2, s2, q):
    inv = pow((c1 - c2) % q, -1, q)
    x = ((s1 - s2) * inv) % q
    k = (s1 - c1 * x) % q
    return x, k
# Signe un challenge selon SDSA Schnorr (cf formules)
def sign_schnorr(challenge: str, x, k, p, q, g):
    r = pow(g, k, p)
    rb = r.to_bytes((r.bit_length() + 7)//8, 'big')
    z = int.from_bytes(hashlib.sha256(challenge.encode() + rb).digest(), 'big') % q
    s = (k + z * x) % q
    return z, s  # (c,s)

def verify(challenge, c, s, x, p, q, g):
    h = pow(g, x, p)
    r = (pow(g, s, p) * pow(h, -c, p)) % p
    rb = r.to_bytes((r.bit_length() + 7)//8, 'big')
    c2 = int.from_bytes(hashlib.sha256(challenge.encode() + rb).digest(), 'big') % q
    return c == c2

if __name__ == "__main__":
    # 1) Public params
    p, q, g = load_dsa_params(PUBKEY_PEM)

    # 2) Extraire (c1,s1),(c2,s2) et récupérer (x,k)
    c1, s1 = der_to_cs(SIG1_HEX)
    c2, s2 = der_to_cs(SIG2_HEX)
    if c1 == c2:
        raise SystemExit("Les deux c sont identiques — pas d’attaque possible.")
    x, k = recover_x_k(c1, s1, c2, s2, q)

    # 3) Saisir le challenge, signer, afficher DER hex
    challenge = input("Challenge: ").strip()
    c, s = sign_schnorr(challenge, x, k, p, q, g)
    sig_hex = cs_to_der(c, s).hex()
    print("Signature (DER hex):", sig_hex)

    # 4) (optionnel) vérif locale
    print("Verify:", "OK" if verify(challenge, c, s, x, p, q, g) else "FAIL")
