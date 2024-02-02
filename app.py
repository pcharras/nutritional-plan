from flask import Flask, request, jsonify
from openai import OpenAI
import logging
import jwt
import datetime
import os
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()
secretkey = os.getenv('SECRETKEY')
api_key = os.getenv('API_KEY')
ass_id = os.getenv('ASS_ID')
url = os.getenv('URL')
url2 = os.getenv('URL2')
url3 = os.getenv('URL3')

app = Flask(__name__)

cors = CORS(app, resources={r"*": {"origins": [url,url2,url3]}})

# Configuración de logueo
logging.basicConfig(level=logging.INFO)

SECRET_KEY = secretkey

client = OpenAI(api_key=api_key)
assistant = client.beta.assistants.retrieve(ass_id)
                                            
instruc = assistant.instructions

def generar_token(usuario_id, thread_id):
    """
    Genera un token JWT para un usuario y un hilo (thread) específico.
    """
    payload = {
        'usuario_id': usuario_id,
        'thread_id': thread_id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # Expira en 1 hora
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    return token


class TokenError(Exception):
    pass

def verificar_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return {'usuario_id': payload['usuario_id'], 'thread_id': payload['thread_id']}
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError) as e:
        raise TokenError(str(e))


def crear_thread():   
    thread = client.beta.threads.create()
    return thread

def get_completion_from_messages(message,thread_id,instruc):

            fin_conversacion = False

            message = client.beta.threads.messages.create(
                thread_id=thread_id,
                role="user",
                content=message
            )

            run = client.beta.threads.runs.create(
            thread_id=thread_id,
            assistant_id="asst_VaHw6slZhdBsXwrlDZgi7Fnn",
            instructions=instruc
            )

            status = "in_progress"
            while status == "queued" or status == "in_progress" or status == "requires_action":
                run = client.beta.threads.runs.retrieve(
                    thread_id=thread_id,
                    run_id=run.id
                )
                status = run.status
                #print(status)

                if status == "requires_action":
                    print(f"Entre una vez")
                    print(status)
                    print(run.required_action.submit_tool_outputs.tool_calls[0].id)
                    call_id = run.required_action.submit_tool_outputs.tool_calls[0].id
                    run = client.beta.threads.runs.submit_tool_outputs(
                    thread_id= thread_id,
                    run_id=run.id,
                    tool_outputs=[
                        {
                        "tool_call_id": call_id,
                        "output": "true"
                        }
                    ]
                    )
                    fin_conversacion = True



            thread_messages = client.beta.threads.messages.list(thread_id)
            return {'mensaje':thread_messages,'fin_conversacion' : fin_conversacion}

def generar_plan(plan):
    {
        print(plan)
    }

@app.route('/')
def index():
    return "Bienvenido a API REST de Plan Nutricional"

@app.route('/plan', methods=['POST'])
def crear_plan():
    """
    Endpoint para iniciar el proceso de generación del plan de nutrición.
    Crea un nuevo thread y devuelve un token para el seguimiento.
    """
    data = request.json
    usuario_id = data.get('usuario_id')
    
    # crear el thread
    thread = crear_thread()
    thread_id = thread.id
    # Generar token
    token = generar_token(usuario_id,thread_id)
    #Genera la primera pregunta
    info = get_completion_from_messages("Hola",thread.id,instruc)
    print(info)
    mensaje = info['mensaje']
    logging.info(f'Plan creado para el usuario {usuario_id} con thread ID {thread_id}')
    return jsonify({'thread_id': thread_id, 'token': token,'message':mensaje.data[0].content[0].text.value})

@app.route('/preguntas', methods=['POST'])
def manejar_preguntas():
    """
    Endpoint para manejar el flujo de preguntas y respuestas.
    """
    data = request.json
    token = data.get('token')

    # Verificar token
    try:
        token_info = verificar_token(token)
    except TokenError as e:
        return jsonify({'error': str(e)}), 401

    #usuario_id = token_info['usuario_id']
    thread_id = token_info['thread_id']

    respuesta = data.get('respuesta')

    # Aquí manejarías la respuesta y posiblemente prepararías la siguiente pregunta
    logging.info(f'Respuesta recibida: {respuesta} para el token: {token}')

    info = get_completion_from_messages(respuesta,thread_id,instruc)
    mensaje = info['mensaje']
    if info['fin_conversacion']:
        message = "Gracias por contestar las preguntas. Su plan nutricicional le llegará por e-mail"
        generar_plan(mensaje.data[0].content[0].text.value)
    else:
        message = mensaje.data[0].content[0].text.value


    return jsonify({'thread_id': thread_id,'token':token,'message':message})

@app.route('/feedback', methods=['POST'])
def recibir_feedback():
    """
    Endpoint para recibir la retroalimentación del plan de nutrición.
    """
    data = request.json
    token = data.get('token')

        # Verificar token
    token_info = verificar_token(token)
    if not token_info:
        return jsonify({'error': 'Token inválido o expirado'}), 401

    usuario_id = token_info['usuario_id']
    thread_id = token_info['thread_id']
    
    calificacion = data.get('calificacion')
    comentario = data.get('comentario')

    # Aquí procesarías la retroalimentación
    logging.info(f'Feedback recibido con calificación {calificacion} y comentario {comentario}')
    return jsonify({'status': 'Feedback recibido'})

# Manejo de errores (ejemplo básico)
@app.errorhandler(404)
def page_not_found(e):
    logging.error(f'Error 404: {e}')
    return jsonify(error=str(e)), 404

@app.errorhandler(500)
def internal_server_error(e):
    logging.error(f'Error 500: {e}')
    return jsonify(error=str(e)), 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, host='0.0.0.0', port=port)
