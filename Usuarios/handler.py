import hmac
import json
import os
import hashlib
import uuid
import boto3

USUARIO_TABLE = os.environ['USUARIO_TABLE']
UBICACIONES_TABLE = os.environ['UBICACIONES_TABLE']

def registrarUsuario(event, context):
    try:
        nombre=event["requestContext"]["nombre"]
        edad=event["requestContext"]["edad"]
        correo=event["requestContext"]["correo"]
        contrasena=event["requestContext"]["contrasena"]

        # Hashing de la contraseña
        salt = os.urandom(16)
        hash_bytes = hashlib.pbkdf2_hmac(
            'sha256', 
            contrasena.encode('utf-8'), 
            salt, 
            600000
        )

        contrasena_hash = salt.hex() + ":" + hash_bytes.hex()

        usuarioTable=boto3.resource('dynamodb').Table(USUARIO_TABLE)
        usuarioJson={
            'tenant_id': correo,
            'nombre': nombre,
            'edad': edad,
            'uuid': str(uuid.uuid4()),
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
        correo = event["requestContext"]["correo"]
        contrasena = event["requestContext"]["contrasena"]

        usuarioTable = boto3.resource('dynamodb').Table(USUARIO_TABLE)
        response = usuarioTable.get_item(Key={'tenant_id': correo})
        
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
                'body': json.dumps({'message': 'Login exitoso', 'uuid': response['Item']['uuid']})
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
    correo=event["requestContext"]["correo"]
    nombre=event["requestContext"]["nombre"]
    latitud=event["requestContext"]["latitud"]
    longitud=event["requestContext"]["longitud"]

    ubicacionTable=boto3.resource('dynamodb').Table(UBICACIONES_TABLE)
    ubicacionJson={
        'tenant_id': correo,
        'nombre': nombre,
        'latitud': latitud,
        'longitud': longitud,
        'uuid': str(uuid.uuid4())
    }
    ubicacionTable.put_item(Item=ubicacionJson)

    return {
        'statusCode': 200,
        'body': json.dumps({'message': 'Ubicación almacenada exitosamente'})
    }