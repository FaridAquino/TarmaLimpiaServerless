import hmac
import json
import os
import hashlib
import uuid
import boto3
from decimal import Decimal

USUARIOS_TABLE = os.environ['USUARIOS_TABLE']
UBICACIONES_TABLE = os.environ['UBICACIONES_TABLE']
CONNECTIONS_TABLE = os.environ['CONNECTIONS_TABLE']

def registrarUsuario(event, context):
    try:
        if 'body' not in event or event['body'] is None:
            return {'statusCode': 400, 'body': json.dumps({'error': 'No se envió cuerpo (body) en la petición'})}
        
        body = json.loads(event['body'])

        nombre=body["nombre"]
        edad=body["edad"]
        correo=body["correo"]
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

        usuarioTable=boto3.resource('dynamodb').Table(USUARIOS_TABLE)
        usuarioJson={
            'tenant_id': nombre,
            'uuid':correo,
            'edad': edad,
            'contrasena_hash': contrasena_hash
        }
        usuarioTable.put_item(Item=usuarioJson) 

        return {
            'statusCode': 200,
            'body': json.dumps({'message': 'Usuario registrado exitosamente'})
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error en registrar usuario': str(e)})
        }

def loginUsuario(event, context):
    try:
        
        if 'body' not in event or event['body'] is None:
            return {'statusCode': 400, 'body': json.dumps({'error': 'No se envió cuerpo (body) en la petición'})}
        
        body = json.loads(event['body'])
        
        correo = body["correo"]
        contrasena = body["contrasena"]
        nombre=body["nombre"]

        usuarioTable = boto3.resource('dynamodb').Table(USUARIOS_TABLE)
        response = usuarioTable.get_item(Key={'tenant_id': nombre, 'uuid': correo})
        
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

def publicarUbicacion(event, context):
    try:
        if 'body' not in event or event['body'] is None:
            return {'statusCode': 400, 'body': json.dumps({'error': 'No se envió cuerpo (body)'})}
        
        body = json.loads(event['body']) 
        
        correo = body.get("correo")
        nombre = body.get("nombre")
        calle = body.get("calle")
        rutas = body.get("rutas")  # Asumiendo que "rutas" es una lista de rutas asociadas al usuario
        
        try:
            lat_float = float(body["latitud"])
            lon_float = float(body["longitud"])
        except (ValueError, TypeError):
            return {
                'statusCode': 400, 
                'body': json.dumps({'error': 'Latitud y Longitud deben ser números válidos'})
            }

        if not (-90 <= lat_float <= 90):
            return {'statusCode': 400, 'body': json.dumps({'error': 'Latitud inválida (debe estar entre -90 y 90)'})}
        
        if not (-180 <= lon_float <= 180):
            return {'statusCode': 400, 'body': json.dumps({'error': 'Longitud inválida (debe estar entre -180 y 180)'})}

        lat_decimal = Decimal(str(lat_float))
        lon_decimal = Decimal(str(lon_float))

        ubicacionTable = boto3.resource('dynamodb').Table(UBICACIONES_TABLE)
        
        ubicacionJson = {
            'tenant_id': nombre,
            'latitud': lat_decimal,   
            'longitud': lon_decimal,
            'calle': calle,
            'uuid': correo,
            'rutas': rutas
        }
        
        ubicacionTable.put_item(Item=ubicacionJson)

        return {
            'statusCode': 200,
            'body': json.dumps({'message': 'Ubicación almacenada exitosamente'})
        }

    except KeyError as e:
        return {'statusCode': 400, 'body': json.dumps({'error': f'Falta el campo: {str(e)}'})}
    except Exception as e:
        print(e)
        return {'statusCode': 500, 'body': json.dumps({'error': str(e)})}