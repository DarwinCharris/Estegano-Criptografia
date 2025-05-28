import os
import base64
from flask import Flask, request
from flask_socketio import SocketIO, emit, join_room
from PIL import Image
from io import BytesIO
from oqs import KeyEncapsulation
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from estegano.ocultar import ocultar_texto
from estegano.leer import leer_mensaje_desde_imagen

# Config
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading",
    max_http_buffer_size=50_000_000
)

UPLOAD_FOLDER = "uploads"
PROCESSED_FOLDER = "procesadas"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(PROCESSED_FOLDER, exist_ok=True)

connected_users = {}
public_keys = {}
kem_objects = {}  # Store KeyEncapsulation objects
KEM_ALGORITHM = "Kyber512"

# Cryptographic functions
def generar_y_guardar_claves(nombre_usuario: str) -> tuple[str, KeyEncapsulation]:
    try:
        kem = KeyEncapsulation(KEM_ALGORITHM)
        public_key = kem.generate_keypair()
        private_key = kem.export_secret_key()

        public_b64 = base64.b64encode(public_key).decode()
        private_b64 = base64.b64encode(private_key).decode()

        os.makedirs("pq_keys", exist_ok=True)
        with open(f"pq_keys/{nombre_usuario}_public.key", "w") as f_pub, \
             open(f"pq_keys/{nombre_usuario}_private.key", "w") as f_priv:
            f_pub.write(public_b64)
            f_priv.write(private_b64)

        print(f"🔑 Claves {KEM_ALGORITHM} generadas para '{nombre_usuario}'")
        return public_b64, kem
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

@app.route('/')
def index():
    return "WebSocket Chat Server Running"

@socketio.on('connect')
def on_connect():
    print("Client connected.")

@socketio.on('disconnect')
def on_disconnect():
    for user, sid in list(connected_users.items()):
        if sid == request.sid:
            print(f"{user} disconnected.")
            del connected_users[user]
            kem_objects.pop(user, None)
            break

@socketio.on('register')
def handle_register(data):
    username = data.get('username')
    if username in ['A', 'B']:
        connected_users[username] = request.sid
        join_room(username)
        public_key, kem = generar_y_guardar_claves(username)
        public_keys[username] = public_key
        kem_objects[username] = kem
        emit('registered', {'message': f'{username} conectado.'}, room=username)
        print(f"{username} registrado con SID {request.sid}")

        if 'A' in connected_users and 'B' in connected_users:
            emit('key_exchange', {
                'peer': 'B',
                'peer_public_key': public_keys['B']
            }, room=connected_users['A'])

            emit('key_exchange', {
                'peer': 'A',
                'peer_public_key': public_keys['A']
            }, room=connected_users['B'])

            for user in ['A', 'B']:
                emit('ready', {'message': 'Ambos usuarios están conectados.'}, room=connected_users[user])
    else:
        emit('error', {'message': 'Usuario inválido (solo A o B permitido)'})

@socketio.on('send_image_message')
def handle_send_image_message(data):
    sender = data.get('sender')
    recipient = data.get('recipient')
    message = data.get('message')
    image_data = data.get('image')

    if not all([sender, recipient, message, image_data]):
        emit('image_too_small', {'message': 'Faltan datos.'}, room=connected_users.get(sender))
        return

    try:
        recipient_public_key = public_keys.get(recipient)
        if not recipient_public_key:
            emit('error', {'message': 'Clave pública del receptor no encontrada.'}, room=connected_users.get(sender))
            return

        ciphertext_b64, shared_secret_b64 = encapsular_clave(recipient_public_key)
    
        # Usar el secreto compartido como clave AES
        aes_key = base64.b64decode(shared_secret_b64)

        # Encriptar el mensaje con AES usando el secreto compartido
        cipher = AES.new(aes_key, AES.MODE_CBC)
        iv = cipher.iv
        ciphertext = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
        encrypted_message = base64.b64encode(iv + ciphertext).decode('utf-8')

    # Combinar el texto cifrado del KEM y el mensaje encriptado
        combined_message = f"{ciphertext_b64}:{encrypted_message}"

        # Process image
        header, b64data = image_data.split(',', 1)
        image_bytes = base64.b64decode(b64data)
        original_img = Image.open(BytesIO(image_bytes))

        input_path = os.path.join(UPLOAD_FOLDER, f"{sender}_original.png")
        original_img.save(input_path)

        output_path = os.path.join(PROCESSED_FOLDER, f"{sender}_oculta.png")
        ocultar_texto(combined_message, input_path, output_path)

        # Extract and validate message
        mensaje_extraido = leer_mensaje_desde_imagen(output_path)
        ciphertext_b64_extracted, encrypted_message_extracted = mensaje_extraido.split(':', 1)
    
    # Desencapsular para obtener el secreto compartido
        kem_recipient = kem_objects.get(recipient)
        shared_secret_b64_decapsulated = desencapsular_clave(ciphertext_b64_extracted, kem_recipient)
        aes_key_decapsulated = base64.b64decode(shared_secret_b64_decapsulated)

    # Desencriptar el mensaje
        encrypted_data = base64.b64decode(encrypted_message_extracted)
        iv, ciphertext = encrypted_data[:16], encrypted_data[16:]
        decipher = AES.new(aes_key_decapsulated, AES.MODE_CBC, iv=iv)
        decrypted_message = unpad(decipher.decrypt(ciphertext), AES.block_size).decode('utf-8')

        # Send processed image
        with open(output_path, 'rb') as img_file:
            processed_b64 = base64.b64encode(img_file.read()).decode('utf-8')
            processed_b64 = f"data:image/png;base64,{processed_b64}"

        # Send to recipient
        emit('receive_image_message', {
            'sender': sender,
            'image': processed_b64,
            'message': decrypted_message
        }, room=connected_users[recipient])

        print(f"Message sent from {sender} to {recipient}")

        # Confirm to sender
        emit('message_sent_ok', {
            'message': message,
            'image': processed_b64
        }, room=connected_users.get(sender))

    except ValueError as ve:
        print(f"[ERROR desencapsulando mensaje]: {ve}")
        emit('error', {
            'message': f'Error en desencapsulación: {str(ve)}'
        }, room=connected_users.get(sender))
    except Exception as e:
        print(f"[ERROR ocultando mensaje]: {e}")
        emit('error', {
            'message': 'No se pudo procesar el mensaje. Posible problema con la imagen o cifrado.'
        }, room=connected_users.get(sender))

if __name__ == '__main__':
    print("Iniciando servidor WebSocket...")
    socketio.run(app, port=5000)