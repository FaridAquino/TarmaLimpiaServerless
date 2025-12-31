import json
import boto3
import os
import firebase_admin
from firebase_admin import credentials, messaging
from boto3.dynamodb.conditions import Key

from botocore.exceptions import ClientError

if not firebase_admin._apps:
    cred = credentials.Certificate("serviceAccountKey.json") # Asegúrate de subir este archivo con tu lambda
    firebase_admin.initialize_app(cred)

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(os.environ['USERS_DEVICES'])

USERS_DEVICES_TABLE = os.environ['USERS_DEVICES']

def registrarToken(event, context):
    try:
        if 'body' not in event or event['body'] is None:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Falta el body'})
            }

        body = json.loads(event['body'])

        correo = body.get('correo')
        device_token = body.get('device_token')
        
        if not correo or not device_token:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Faltan datos (correo o device_token)'})
            }

        usersDevicesTable = boto3.resource('dynamodb').Table(USERS_DEVICES_TABLE)
        
        usersDevicesJson = {
            'tenant_id': correo,
            'uuid': device_token
        }
        
        try:
            usersDevicesTable.put_item(
                Item=usersDevicesJson,
                ConditionExpression='attribute_not_exists(tenant_id)'
            )
            
            return {
                'statusCode': 200,
                'body': json.dumps({'message': 'Token registrado exitosamente'})
            }

        except ClientError as e:
            if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
                print(f"El token para {correo} ya existía. No se hizo nada.")
                return {
                    'statusCode': 200, # Retornamos 200 OK porque la solicitud fue procesada correctamente
                    'body': json.dumps({
                        'message': 'El dispositivo ya estaba registrado. No se realizaron cambios.',
                        'status': 'skipped'
                    })
                }
            else:
                raise e

    except Exception as e:
        print(f"Error crítico: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def lambda_handler(event, context):
    print("Evento recibido de SNS:", json.dumps(event))
    print(f"--- [DEBUG] Versión Firebase en Lambda: {firebase_admin.__version__} ---")
    for record in event['Records']:
        try:
            sns_message = json.loads(record['Sns']['Message'])
            process_message(sns_message)
        except Exception as e:
            print(f"Error procesando registro SNS: {e}")
            
    return {'statusCode': 200, 'body': 'Procesado'}

def process_message(data):
    # Data esperada: {'correos': ['usuario1@gmail.com'], 'title': '...', 'body': '...'}
    target_users = data.get('correos', [])
    titulo = data.get('title', 'Notificación')
    cuerpo = data.get('body', 'Nueva alerta')
    
    if not target_users:
        print("No hay usuarios destino.")
        return

    tokens_to_send = []
    
    # 1. Obtener tokens de DynamoDB
    for tenant_id in target_users:
        try:
            response = table.query(
                KeyConditionExpression=Key('tenant_id').eq(tenant_id)
            )
            items = response.get('Items', [])
            for item in items:
                # Ojo: Asegúrate si en tu BD guardaste como 'uuid' o 'fcm_token'
                # Según tu código anterior era 'uuid' (que usabas para el token)
                if 'uuid' in item: 
                    tokens_to_send.append(item['uuid'])
        except Exception as e:
            print(f"Error consultando DynamoDB para {tenant_id}: {e}")
            
    if not tokens_to_send:
        print("No se encontraron tokens válidos en BD.")
        return
    
    # Limpiamos duplicados
    tokens_to_send = list(set(tokens_to_send))

    print(f"--- [MODO SEGURO] Enviando 1 por 1 a {len(tokens_to_send)} dispositivos ---")

    # 2. BUCLE DE ENVÍO INDIVIDUAL (A prueba de fallos)
    enviados = 0
    errores = 0

    for token in tokens_to_send:
        try:
            # Creamos un mensaje individual para cada token
            msg = messaging.Message(
                notification=messaging.Notification(
                    title=titulo,
                    body=cuerpo,
                ),
                data={'click_action': 'FLUTTER_NOTIFICATION_CLICK'},
                token=token # <--- IMPORTANTE: Usamos 'token' (singular)
            )
            
            # Usamos .send() que es la función básica universal
            response = messaging.send(msg)
            enviados += 1
            # print(f"Enviado OK. ID: {response}") # Descomentar si quieres mucho detalle
            
        except Exception as e:
            print(f"Error enviando a token {token[:10]}...: {e}")
            errores += 1
            # Aquí podrías agregar lógica: Si el error dice "Unregistered", borrar de DynamoDB.

    print(f"--- Resultado Final: {enviados} enviados, {errores} fallidos ---")


