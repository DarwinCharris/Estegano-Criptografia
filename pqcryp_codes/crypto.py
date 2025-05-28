import os
import base64
from base64 import b64decode
from oqs import KeyEncapsulation
from typing import Tuple

KEM_ALGORITHM = "Kyber512"

def generar_y_guardar_claves(nombre_usuario):
    try:
        kem = KeyEncapsulation(KEM_ALGORITHM)
        public_key = kem.generate_keypair()
        private_key = kem.export_secret_key()

        # Codificación base64
        public_b64 = base64.b64encode(public_key).decode()
        private_b64 = base64.b64encode(private_key).decode()

        # Guardar claves
        os.makedirs("pq_keys", exist_ok=True)
        with open(f"pq_keys/{nombre_usuario}_public.key", "w") as f_pub, \
             open(f"pq_keys/{nombre_usuario}_private.key", "w") as f_priv:
            f_pub.write(public_b64)
            f_priv.write(private_b64)

        print(f"🔑 Claves {KEM_ALGORITHM} generadas para '{nombre_usuario}'")
        return public_b64, kem  # Devolvemos clave pública y objeto kem
    except Exception as e:
        raise RuntimeError(f"Error generando claves: {str(e)}")

def encapsular_clave(public_key_b64: str) -> tuple[str, str]:
    try:
        kem = KeyEncapsulation(KEM_ALGORITHM)
        public_key = base64.b64decode(public_key_b64)
        ciphertext, shared_secret = kem.encap_secret(public_key)
        return base64.b64encode(ciphertext).decode(), base64.b64encode(shared_secret).decode()
    except Exception as e:
        raise RuntimeError(f"Error encapsulando clave: {str(e)}")

def desencapsular_clave(ciphertext_b64: str, kem: KeyEncapsulation) -> str:
    try:
        shared_secret = kem.decap_secret(base64.b64decode(ciphertext_b64))
        return base64.b64encode(shared_secret).decode()
    except Exception as e:
        raise RuntimeError(f"Error desencapsulando: {str(e)}")

    """try:
        kem = KeyEncapsulation(KEM_ALGORITHM)
        kem.import_secret_key(base64.b64decode(private_key_b64))
        
        shared_secret = kem.decap_secret(base64.b64decode(ciphertext_b64))
        return base64.b64encode(shared_secret).decode()
    
    except Exception as e:
        raise RuntimeError(f"Error desencapsulando: {str(e)}")"""




