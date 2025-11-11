from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from datetime import datetime
import uvicorn
from typing import Optional
import hashlib

from acr122u_reader import ACR122UReader
from database import DatabaseManager
from blockchain_simulated import BlockchainSimulated

app = FastAPI(title="Sistema de Autenticación NFC + Blockchain")

# Modelos de datos
class AuthRequest(BaseModel):
    pin: str
    nfc_id: str
    device_id: str

class AuthResponse(BaseModel):
    success: bool
    message: str
    user: Optional[dict]
    blockchain_tx: Optional[str]

# Inicializar componentes
nfc_reader = ACR122UReader()
database = DatabaseManager()
blockchain = BlockchainSimulated()

# Simulador de Active Directory (para pruebas)
active_directory_users = {
    "analopez": {"pin": "1234", "full_name": "Ana Lopez", "department": "Inteligencia"},
    "carlosruiz": {"pin": "5678", "full_name": "Carlos Ruiz", "department": "Analisis"},
    "mariatorres": {"pin": "9012", "full_name": "Maria Torres", "department": "Operaciones"},
    "aimee": {"pin": "0000", "full_name": "Aimee", "department": "Desarrollo"}  
    }

@app.post("/authenticate", response_model=AuthResponse)
async def authenticate_user(auth_request: AuthRequest):
    try:
        print(f"🔐 Intento de autenticación: NFC={auth_request.nfc_id}")
        
        # 1. Verificar tarjeta NFC en base de datos
        nfc_user = database.get_user_by_nfc(auth_request.nfc_id)
        if not nfc_user:
            # Registrar intento fallido
            tx_hash = blockchain.record_auth_attempt(
                user_id="unknown",
                timestamp=datetime.now().timestamp(),
                device_id=auth_request.device_id,
                nfc_id=auth_request.nfc_id,
                success=False
            )
            database.log_auth_attempt(0, auth_request.nfc_id, auth_request.device_id, False, tx_hash, "Tarjeta no registrada")
            return AuthResponse(
                success=False,
                message="Tarjeta NFC no registrada en el sistema",
                blockchain_tx=tx_hash
            )
        
        # 2. Verificar PIN con Active Directory (simulado)
        ad_user = active_directory_users.get(nfc_user['username'])
        if not ad_user or ad_user['pin'] != auth_request.pin:
            # Registrar intento fallido
            tx_hash = blockchain.record_auth_attempt(
                user_id=nfc_user['username'],
                timestamp=datetime.now().timestamp(),
                device_id=auth_request.device_id,
                nfc_id=auth_request.nfc_id,
                success=False
            )
            database.log_auth_attempt(nfc_user['id'], auth_request.nfc_id, auth_request.device_id, False, tx_hash, "PIN incorrecto")
            return AuthResponse(
                success=False,
                message="Credenciales inválidas",
                blockchain_tx=tx_hash
            )
        
        # 3. Autenticación exitosa
        tx_hash = blockchain.record_auth_attempt(
            user_id=nfc_user['username'],
            timestamp=datetime.now().timestamp(),
            device_id=auth_request.device_id,
            nfc_id=auth_request.nfc_id,
            success=True
        )
        
        database.log_auth_attempt(nfc_user['id'], auth_request.nfc_id, auth_request.device_id, True, tx_hash)
        
        return AuthResponse(
            success=True,
            message="Autenticación exitosa",
            user={
                "username": nfc_user['username'],
                "full_name": ad_user['full_name'],
                "department": ad_user['department'],
                "security_level": nfc_user['security_level']
            },
            blockchain_tx=tx_hash
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno: {str(e)}")

@app.get("/user/{nfc_id}")
async def get_user_by_nfc(nfc_id: str):
    user = database.get_user_by_nfc(nfc_id)
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    return user

@app.get("/logs")
async def get_auth_logs(limit: int = 20):
    return database.get_auth_logs(limit)

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "nfc_reader": "connected" if nfc_reader.reader else "disconnected",
        "database": "connected",
        "blockchain": "simulated"
    }

if __name__ == "__main__":
    print("🚀 Iniciando Servidor de Autenticación NFC + Blockchain")
    print("📍 Servidor disponible en: http://localhost:8000")
    print("📚 Documentación API: http://localhost:8000/docs")
    uvicorn.run(app, host="0.0.0.0", port=8000)