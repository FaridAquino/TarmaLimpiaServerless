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
            'uuid': correo
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

#WEBSOCKET

def transmitir(event, message_payload_dict):
    try:
        connections_table = boto3.resource('dynamodb').Table(CONNECTIONS_TABLE)
    except Exception as e:
        print(f"[Error Transmitir] No se pudieron cargar las tablas: {e}")
        return
    
    try:
        endpoint_url = f"https://{event['requestContext']['domainName']}/{event['requestContext']['stage']}"
        apigateway_client = boto3.client('apigatewaymanagementapi', endpoint_url=endpoint_url)
    except KeyError:
        print(f"[Error Transmitir] El evento no tiene 'requestContext' para el endpoint_url.")
        return

    pedido_data = message_payload_dict.get('pedido', {})
    
    if not pedido_data:
        print("[Error Transmitir] No se encontró el objeto 'pedido' en el payload.")
        return

    try:
        response = connections_table.scan(ProjectionExpression='connectionId, #r',ExpressionAttributeNames={'#r': 'role'})
        connections = response.get('Items', [])
    except Exception as e:
        print(f"[Error Transmitir] Fallo al escanear la tabla de conexiones: {e}")
        return

    print(f"Encontradas {len(connections)} conexiones para evaluar.")
    
    message_payload_str = json.dumps(message_payload_dict)
    chefs_found = 0

    for connection in connections:
        connection_id = connection['connectionId']
        user_role = connection.get('role', 'CLIENTE')
        
        if user_role == 'CHEF':
            chefs_found += 1
            try:
                apigateway_client.post_to_connection(
                    ConnectionId=connection_id,
                    Data=message_payload_str.encode('utf-8')
                )
                print(f"[Info Transmitir] Pedido enviado a chef: {connection_id}")
            except apigateway_client.exceptions.GoneException:
                print(f"[Info Transmitir] Conexión de chef muerta {connection_id}. Limpiando.")
                connections_table.delete_item(Key={'connectionId': connection_id})
            except Exception as e:
                print(f"[Error Transmitir] No se pudo enviar a chef {connection_id}: {e}")
        else:
            print(f"[Info Transmitir] Saltando conexión {connection_id} - Rol: {user_role} (no es chef)")
    
    print(f"[Info Transmitir] Pedido transmitido a {chefs_found} chefs conectados.")

def connection_manager(event, context):
    connection_id = event['requestContext']['connectionId']
    route_key = event['requestContext']['routeKey']

    query_params = event.get('queryStringParameters', {}) or {}

    if not CONNECTIONS_TABLE:
        print("Error: CONNECTIONS_TABLE no está definida en las variables de entorno.")
        return {'statusCode': 500, 'body': 'Error de configuración del servidor.'}
        
    table = boto3.resource("dynamodb").Table(CONNECTIONS_TABLE)

    if route_key == '$connect':
        try:
            
            item = {
                'connectionId': connection_id,
                'role': query_params.get('role', 'CLIENTE'),
            }

            table.put_item(Item=item)
            
            return {'statusCode': 200, 'body': 'Conectado.'}

        except Exception as e:
            print(f"Error en $connect: {e}")
            return {'statusCode': 500, 'body': 'Fallo en $connect.'}

    elif route_key == '$disconnect':
        try:
            table.delete_item(
                Key={'connectionId': connection_id}
            )
            print(f"Conexión eliminada: {connection_id}")
            
            return {'statusCode': 200, 'body': 'Desconectado.'}
            
        except Exception as e:
            print(f"Error en $disconnect (no crítico): {e}")
            return {'statusCode': 200, 'body': 'Desconectado con error de limpieza.'}

    return {'statusCode': 500, 'body': 'Error en connection_manager.'}

def default_handler(event, context):
    print(f"Ruta $default invocada. Evento: {event}")
    return {
        'statusCode': 404,
        'body': json.dumps("Acción no reconocida.")
    }
