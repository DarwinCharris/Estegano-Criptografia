import os
import base64
from flask import Flask, request
from flask_socketio import SocketIO, emit, join_room
from PIL import Image
from io import BytesIO

from estegano.ocultar import ocultar_texto
from estegano.leer import leer_mensaje_desde_imagen

# Config
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="eventlet",
    max_http_buffer_size=50_000_000
)

UPLOAD_FOLDER = "uploads"
PROCESSED_FOLDER = "procesadas"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(PROCESSED_FOLDER, exist_ok=True)

connected_users = {}

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
            break

@socketio.on('register')
def handle_register(data):
    username = data.get('username')
    if username in ['A', 'B']:
        connected_users[username] = request.sid
        join_room(username)
        emit('registered', {'message': f'{username} conectado.'}, room=username)
        print(f"{username} registrado con SID {request.sid}")

        if 'A' in connected_users and 'B' in connected_users:
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
        # Procesar imagen
        header, b64data = image_data.split(',', 1)
        image_bytes = base64.b64decode(b64data)
        original_img = Image.open(BytesIO(image_bytes))

        input_path = os.path.join(UPLOAD_FOLDER, f"{sender}_original.png")
        original_img.save(input_path)

        output_path = os.path.join(PROCESSED_FOLDER, f"{sender}_oculta.png")
        ocultar_texto(message, input_path, output_path)

        mensaje_extraido = leer_mensaje_desde_imagen(output_path)

        with open(output_path, 'rb') as img_file:
            processed_b64 = base64.b64encode(img_file.read()).decode()
            processed_b64 = f"data:image/png;base64,{processed_b64}"

        # Enviar a receptor
        emit('receive_image_message', {
            'sender': sender,
            'image': processed_b64,
            'message': mensaje_extraido
        }, room=connected_users[recipient])

        # Confirmar al emisor
        emit('message_sent_ok', {
            'message': message,
            'image': processed_b64
        }, room=connected_users.get(sender))

    except Exception as e:
        print(f"[ERROR ocultando mensaje]: {e}")
        emit('image_too_small', {
            'message': 'No se pudo ocultar el mensaje. Imagen muy pequeña.'
        }, room=connected_users.get(sender))

if __name__ == '__main__':
    print("Iniciando servidor WebSocket...")
    socketio.run(app, port=5000)
