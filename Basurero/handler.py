import json
import hmac
import os
import boto3
import hashlib
from decimal import Decimal

RUTAS_TABLE = os.environ.get('RUTA_TABLE')
BASURERO_TABLE=os.environ.get('BASURERO_TABLE')

def registrarRuta(event, context):
    try:
        if 'body' not in event or event['body'] is None:
            return {'statusCode': 400, 'body': json.dumps({'error': 'Falta el body'})}

        body = json.loads(event['body'])

        # Datos de entrada
        ruta_id = body["ruta_id"]
        origen_id = body["origen_id"] 
        
        # Datos descriptivos
        nombre_calle = body.get("nombre_calle", "Desconocida")
        
        # Coordenadas (Convertimos a Decimal para DynamoDB)
        lat_origen = Decimal(str(body["lat_origen"]))
        lng_origen = Decimal(str(body["lng_origen"]))
        lat_destino = Decimal(str(body["lat_destino"]))
        lng_destino = Decimal(str(body["lng_destino"]))

        try:
            rutasTable = boto3.resource('dynamodb').Table(RUTAS_TABLE)
        except Exception as e:
            print(f"Error al conectar con la tabla de rutas: {e}")
            return {
                'statusCode': 500,
                'body': json.dumps({'error': 'Error de conexión con la base de datos'})
            }
        
        # Estructura de la Arista (Edge)
        rutaItem = {
            'tenant_id': ruta_id,   # PK
            'uuid': origen_id, # SK
            'nombre_calle': nombre_calle,
            'coordenadas_origen': {'lat': lat_origen, 'lng': lng_origen},
            'coordenadas_destino': {'lat': lat_destino, 'lng': lng_destino},
            'tipo': 'arista_grafo'
        }

        rutasTable.put_item(Item=rutaItem)

        return {
            'statusCode': 200,
            'body': json.dumps({'message': 'Tramo de ruta registrado exitosamente'})
        }

    except Exception as e:
        print(e)
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def registerBasurero(event, context):
    try:
        if 'body' not in event or event['body'] is None:
            return {'statusCode': 400, 'body': json.dumps({'error': 'Falta el body'})}

        body = json.loads(event['body'])

        nombre = body['nombre']
        correo = body['correo']

        contrasena=body["contrasena"]

        # Hashing de la contraseña
        salt = os.urandom(16)
        hash_bytes = hashlib.pbkdf2_hmac(
            'sha256', 
            contrasena.encode('utf-8'), 
            salt, 
            600000
        )

        contrasena_hash = salt.hex() + ":" + hash_bytes.hex()

        basureroTable = boto3.resource('dynamodb').Table(BASURERO_TABLE)
        
        basureroJson = {
            'tenant_id': nombre,
            'uuid': correo,
            'contrasena_hash': contrasena_hash
        }
        
        basureroTable.put_item(Item=basureroJson)

        return {
            'statusCode': 200,
            'body': json.dumps({'message': 'Basurero registrado exitosamente'})
        }

    except KeyError as e:
        return {'statusCode': 400, 'body': json.dumps({'error': f'Falta el campo: {str(e)}'})}
    except Exception as e:
        print(e)
        return {'statusCode': 500, 'body': json.dumps({'error': str(e)})}

def loginBasurero(event, context):
    try:
        if 'body' not in event or event['body'] is None:
            return {'statusCode': 400, 'body': json.dumps({'error': 'Falta el body'})}

        body = json.loads(event['body'])

        nombre = body['nombre']
        correo = body['correo']
        contrasena = body["contrasena"]


        basureroTable = boto3.resource('dynamodb').Table(BASURERO_TABLE)
        
        response = basureroTable.get_item(Key={'tenant_id': nombre, 'uuid': correo})
        
        if 'Item' not in response:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Usuario no encontrado'})
            }

        contrasena_guardada = response['Item']['contrasena_hash']
        
        try:
            salt_hex, hash_real_hex = contrasena_guardada.split(":")
        except ValueError:
            return {'statusCode': 500, 'body': json.dumps({'error': 'Error en datos de usuario'})}

        salt_bytes = bytes.fromhex(salt_hex)

        hash_intento = hashlib.pbkdf2_hmac(
            'sha256',
            contrasena.encode('utf-8'),
            salt_bytes,
            600000
        )

        hash_real_bytes = bytes.fromhex(hash_real_hex)
        
        if hmac.compare_digest(hash_intento, hash_real_bytes):
            return {
                'statusCode': 200,
                'body': json.dumps({'message': 'Login exitoso'})
            }
        else:
            return {
                'statusCode': 401,
                'body': json.dumps({'error': 'Contraseña incorrecta'})
            }

    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

    except KeyError as e:
        return {'statusCode': 400, 'body': json.dumps({'error': f'Falta el campo: {str(e)}'})}
    except Exception as e:
        print(e)
        return {'statusCode': 500, 'body': json.dumps({'error': str(e)})}
