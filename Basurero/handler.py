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

