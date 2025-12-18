import json
import os
import boto3
import uuid
from decimal import Decimal

RUTAS_TABLE = os.environ.get('RUTA_TABLE')
UBICACION_BASURERO_TABLE= os.environ.get('UBICACION_BASURERO_TABLE')
CONNECTIONS_TABLE = os.environ.get('CONNECTIONS_TABLE')
UBICACIONES_USUARIOS_TABLE = os.environ.get('UBICACIONES_USUARIOS_TABLE')
def registrarRuta(event, context):
    try:
        if 'body' not in event or event['body'] is None:
            return {'statusCode': 400, 'body': json.dumps({'error': 'Falta el body'})}

        body = json.loads(event['body'])

        # Datos de entrada
        ruta_id = body.get("ruta_id")
        origen_id = body["origen_id"] 
        destino_id = body["destino_id"]
        
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
            'tenant_id': origen_id,   # PK
            'uuid': destino_id, # SK
            'ruta_id': ruta_id,
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

#WEBSOCKET

def transmitir(event, message_payload_dict):
    if not CONNECTIONS_TABLE or not UBICACIONES_USUARIOS_TABLE:
        print("[Error] Variables de entorno de tablas no definidas.")
        return

    try:
        endpoint_url = f"https://{event['requestContext']['domainName']}/{event['requestContext']['stage']}"
        apigateway_client = boto3.client('apigatewaymanagementapi', endpoint_url=endpoint_url)
    except KeyError:
        print(f"[Error] El evento no tiene 'requestContext' válido.")
        return

    ubicacion_data = message_payload_dict.get('ubicacion', {})
    ruta_basurero = ubicacion_data.get('ruta') # Extraemos la ruta del bus (ej: "Ruta-A")
    
    if not ubicacion_data:
        print("[Error] No hay datos de ubicación.")
        return

    connections_table = boto3.resource('dynamodb').Table(CONNECTIONS_TABLE)
    
    try:
        response = connections_table.scan(
            ProjectionExpression='connectionId, #r, tenant_id, #u', 
            ExpressionAttributeNames={'#r': 'role', '#u': 'uuid'}
        )
        connections = response.get('Items', [])
    except Exception as e:
        print(f"[Error] Fallo al scanear conexiones: {e}")
        return

    print(f"Evaluando {len(connections)} conexiones.")
    
    usuarios_table = boto3.resource('dynamodb').Table(UBICACIONES_USUARIOS_TABLE)
    message_bytes = json.dumps(message_payload_dict).encode('utf-8')

    for connection in connections:
        connection_id = connection['connectionId']
        user_role = connection.get('role', 'USUARIO')
        
        # Validar que tengamos los IDs necesarios antes de seguir
        tenant_id = connection.get('tenant_id')
        user_uuid = connection.get('uuid')

        if user_role == 'USUARIO':
            try:
                apigateway_client.post_to_connection(
                    ConnectionId=connection_id,
                    Data=message_bytes
                )

                # 4. Lógica de "Ruta Cercana"
                # Solo consultamos a DynamoDB si tenemos los IDs y hay una ruta que comprobar
                if ruta_basurero and tenant_id and user_uuid:
                    

                    usuario_resp = usuarios_table.get_item(
                        Key={'tenant_id': tenant_id, 'uuid': user_uuid}
                    )
                    
                    rutas_usuario = usuario_resp.get('Item', {}).get('rutas', [])
                    
                    if ruta_basurero in rutas_usuario:
                        print(f"Usuario {tenant_id} coincide con ruta {ruta_basurero}")
                        
                        payload_alerta = {
                            'action': 'ubicacionCercanaRuta',
                            'ubicacion': ubicacion_data
                        }
                        
                        apigateway_client.post_to_connection(
                            ConnectionId=connection_id,
                            Data=json.dumps(payload_alerta).encode('utf-8')
                        )

            except apigateway_client.exceptions.GoneException:
                print(f"[Limpieza] Eliminando conexión inactiva: {connection_id}")
                connections_table.delete_item(Key={'connectionId': connection_id})
            except Exception as e:
                print(f"[Error] Fallo enviando a {connection_id}: {str(e)}")

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
                'role': query_params.get('role', 'BASURERO'),
            }

            table.put_item(Item=item)

            print(f"Conexión registrada: {connection_id} con rol {item['role']}")
            
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

def publicarUbicacion(event, context):
    print("Evento recibido en publicarUbicacion")

    connection_id = event['requestContext']['connectionId']
    connections_table = boto3.resource("dynamodb").Table(CONNECTIONS_TABLE)

    conn_resp = connections_table.get_item(Key={'connectionId': connection_id})
    
    if 'Item' not in conn_resp:
        print(f"Conexión no encontrada: {connection_id}")
        return {'statusCode': 403, 'body': json.dumps('Conexión no autorizada. Reconecte.')}
    
    if 'body' not in event or event['body'] is None:
            print("Falta el body en el evento")
            return {'statusCode': 400, 'body': json.dumps({'error': 'Falta el body'})}

    body = json.loads(event['body'])
    
    correo = body.get("correo")
    nombre = body.get("nombre")
    calle = body.get("calle")
    ruta_id= body.get("ruta_id")
        
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

    try:
        ubicacionTable = boto3.resource('dynamodb').Table(UBICACION_BASURERO_TABLE)
    except Exception as e:
        print(f"Error al conectar con la tabla de ubicaciones de basurero: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': 'Error de conexión con la base de datos'})
        }

    ubicacionJson = {
        'tenant_id': nombre,
        'uuid': correo,
        'latitud': lat_decimal,   
        'longitud': lon_decimal,
        'calle': calle,
        'ruta_id': ruta_id
    }
    ubicacion={
        'calle': calle,
        'latitud': float(lat_decimal),
        'longitud': float(lon_decimal)
    }

    transmission_payload = {
            'action': 'ubicacionBasurero',
            'ubicacion': ubicacion
        }

    try:
        ubicacionTable.put_item(Item=ubicacionJson)
    except Exception as e:
        print(f"Error al almacenar la ubicación en DynamoDB: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': 'Error al almacenar la ubicación'})
        }
    
    transmitir(event, transmission_payload)

    print("Ubicación almacenada y transmitida exitosamente")

    return {
        'statusCode': 200,
        'body': json.dumps({'message': 'Ubicación almacenada exitosamente'})
    }
