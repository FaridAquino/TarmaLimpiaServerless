import hmac
import json
import os
import hashlib
import boto3
from decimal import Decimal

from boto3.dynamodb.conditions import Key

class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return float(obj)
        return super(DecimalEncoder, self).default(obj)

USUARIOS_TABLE = os.environ['USUARIOS_TABLE']
UBICACIONES_TABLE = os.environ['UBICACIONES_TABLE']
CONNECTIONS_TABLE = os.environ['CONNECTIONS_TABLE']
UBICACION_BASURERO_TABLE=os.environ['UBICACION_BASURERO_TABLE']
RUTAS_TABLE=os.environ['RUTAS_TABLE']

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
            'contrasena_hash': contrasena_hash,
            'registro_completo': False
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
        usuariosTable=boto3.resource('dynamodb').Table(USUARIOS_TABLE)

        ubicacionJson = {
            'tenant_id': nombre,
            'latitud': lat_decimal,   
            'longitud': lon_decimal,
            'calle': calle,
            'uuid': correo,
            'rutas': rutas
        }

        usuariosTable.update_item(
                Key={'tenant_id': nombre, 'uuid': correo},
                UpdateExpression='SET registroCompleto = :val',
                ExpressionAttributeValues={':val': True}
            )
        
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

def obtenerUbicacionBasurero(event, context):
    try:
        if 'body' not in event or event['body'] is None:
            return {'statusCode': 400, 'body': json.dumps({'error': 'No se envió cuerpo (body)'})}
        
        body = json.loads(event['body']) 

        nombreBasurero = body.get("nombreBasurero")
        correoBasurero = body.get("correoBasurero")

        if not nombreBasurero or not correoBasurero:
            return {'statusCode': 400, 'body': json.dumps({'error': 'Faltan parámetros requeridos: nombreBasurero y correoBasurero'})}
        ubicacionTable = boto3.resource('dynamodb').Table(UBICACION_BASURERO_TABLE)
        response = ubicacionTable.get_item(Key={'tenant_id': nombreBasurero, 'uuid': correoBasurero})

        if 'Item' not in response:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Ubicación no encontrada'})
            }

        ubicacion = response['Item']

        calle=ubicacion.get('calle', 'N/A')
        latitud=float(ubicacion.get('latitud', 0))
        longitud=float(ubicacion.get('longitud', 0))
        ruta_id=ubicacion.get('ruta_id', 'N/A')

        ubicacionJson={
            'calle': calle,
            'latitud': latitud,
            'longitud': longitud,
            'ruta_id': ruta_id
        }

        return {
            'statusCode': 200,
            'body': {'ubicacion': ubicacionJson}
        }

    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def getRutas(event, context):
    try:
        rutaTable = boto3.resource('dynamodb').Table(RUTAS_TABLE)
        response = rutaTable.scan()
        rutas = response.get('Items', [])

        return {
            'statusCode': 200,
            'body': json.dumps({'rutas': rutas}, cls=DecimalEncoder)
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def getRutaEspecifica(event, context):
    try:
        query_params = event.get('queryStringParameters')
        
        if not query_params:
            return {'statusCode': 400, 'body': json.dumps({'error': 'Faltan parámetros'})}

        tenant_id = query_params.get('tenant_id')

        if not tenant_id:
            return {'statusCode': 400, 'body': json.dumps({'error': 'Falta el tenant_id'})}

        rutaTable = boto3.resource('dynamodb').Table(RUTAS_TABLE)

        response = rutaTable.query(
            KeyConditionExpression=Key('tenant_id').eq(tenant_id)
        )

        items = response.get('Items', [])

        return {
            'statusCode': 200,
            'body': json.dumps({'rutas': items}, cls=DecimalEncoder)
        }

    except Exception as e:
        print(f"Error: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def registroCompleto(event, context):
    try:
        if 'body' not in event or event['body'] is None:
            return {'statusCode': 400, 'body': json.dumps({'error': 'No se envió cuerpo (body)'})}
        
        body = json.loads(event['body']) 

        nombre = body.get("nombre")
        correo = body.get("correo")

        usuarioTable=boto3.resource('dynamodb').Table(USUARIOS_TABLE)
        response=usuarioTable.get_item(Key={'tenant_id': nombre, 'uuid': correo})
        
        if 'Item' not in response:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Usuario no encontrado'})
            }

        if (response['Item'].get('registro_completo') == True):
            return {
                'statusCode': 200,
                'body': json.dumps({'registro_completo': True})
            }
        else:
            return {
                'statusCode': 200,
                'body': json.dumps({'registro_completo': False})
            }

    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }