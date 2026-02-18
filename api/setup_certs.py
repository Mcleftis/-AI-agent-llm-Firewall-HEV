import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import datetime


CERT_DIR = "certs"

def generate_self_signed_cert():

    if not os.path.exists(CERT_DIR):
        print(f"📂 Creating folder: {CERT_DIR}...")
        os.makedirs(CERT_DIR)

    print("⏳ Generating Private Key (RSA 4096-bit)...")
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )

    print("⏳ Signing Certificate...")
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"GR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Attica"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Athens"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Thesis IoT Project"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    ).sign(key, hashes.SHA256())


    key_path = os.path.join(CERT_DIR, "key.pem")
    cert_path = os.path.join(CERT_DIR, "cert.pem")

    print(f"💾 Saving to {key_path}...")
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    print(f"💾 Saving to {cert_path}...")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print("✅ DONE! Τα πιστοποιητικά βρίσκονται μέσα στον φάκελο 'certs'.")

if __name__ == "__main__":
    generate_self_signed_cert()