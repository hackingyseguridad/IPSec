# IPSec

IPSec (Seguridad del Protocolo de Internet) es un protocolo diseñado para poder conectar y  proteger todo el tráfico de red entre dos redes,  aplicar cifrados, control de integridad a los datos y autenticacin; IPsec es un  protocolo de nivel de enlace que proporcina seguridad, Capa 3, estandarizado para Ipv4, IPv6.

Se establecen dos tuneles por fases:

Fase 1:

IKE ( autenticación )  la fase 1 de IKE es establecer un túnel seguro que podamos usar para la fase 2 de IKE. Negociación. El par que tenga tráfico que deba protegerse iniciará la negociación de fase 1 de IKE. Los dos pares negociarán sobre los siguientes puntos:

· Hashing : usa un algoritmo hash para verificar la integridad, utilizamos MD5 o SHA (SHA-1 o SHA-2).
· Autenticación : utiliza clave precompartida o certificado digital.
· Grupo DH (Diffie Hellman)
· Vida útil :tiempo que dura el túnel IKE p.ej. 86400 segundos (1 día).
· Cifrado : algoritmo utilizado para el cifrado. Por ejemplo: DES , 3DES o AES .

· Encapsulación : Usamos AH o ESP?
· Modo de encapsulación : modo transporte o túnel?

Fase 2:

AH (Cabecera de autenticacion adicional IP, para control integridad, calcula un HASH y MAC clave simetrica, para comprobar en destino), 
ESP (Cifrado, es una etiqueta, encabezado y cola sobre el paquete IP +AH)

ESP (Protocolo de carga útil de seguridad encapsulada): proporciona un método para cifrar datos en paquetes IP.

AH y/o ESP son los dos protocolos que utilizamos para proteger los datos del usuario. Ambos se pueden utilizar en modo transporte o túnel

<img style="float:left" alt="Fases IPSEC" src="https://github.com/hackingyseguridad/IPSec/blob/master/IPSEC.png">


Dos posibles modos de uso; transporte y tunel:

Transporte, es cabecera AH, El modo de transporte es  agrega un encabezado AH después del encabezado IP.

Cabecera IP | Cabecera AH | Cabecera TCP | Datos

Cabecera IP | Cabecera ESP | Cabercera TCP | Datos | ESP Trailer | ESP Auth 

Cabecera IP | Cabecera AH | Cabecera ESP | Cabercera IP | Cabecera TCP | Datos | ESP Trailer | ESP Auth

Tunel, se le etiqueta con IP origen y destino a todo el paquete IP + AH.  el modo túnel agregamos un nuevo encabezado IP encima del paquete IP original. 

Nueva cabecera IP | Cavecera AH | Cabecera IP | Cabercera TCP | Datos

Nueva cabecera IP | Cabecera ESP | Cabercera IP | Cabecera TCP | Datos | ESP Trailer | ESP Auth

Nueva cabecera IP | Cabecera AH | Cabecera ESP | Cabercera IP | Cabecera TCP | Datos | ESP Trailer | ESP Auth  

La  diferencia entre los dos es que con el modo de transporte usaremos el encabezado IP original mientras que en el modo túnel usaremos un nuevo encabezado IP . 
La principal diferencia entre el modo de túnel IPSec y el modo de transporte IPSec es que el modo de túnel se refiere a la tunelización o conexión de dos hosts, y ciertas configuraciones de este modo crean una capa adicional de encabezados para cifrar. Estos encabezados incluyen información para los routers sobre dónde reenviar los paquetes. En cada extremo del túnel, los paquetes intercambiados se descifran para que puedan llegar a los destinos asignados.

En el modo de transporte, por otro lado, los enrutadores intermediarios pueden acceder a la información dentro del encabezado sin descifrarla, excepto la carga útil.

IKEv1, Autenticación previa compartida (PSK) o certificados y cifrados 	MD5, SHA1, DES, 3DES
IKEv2, admite la autenticación EAP (claves precompartida y certificado digital).  tiene soporte integrado para cruce NAT y cifrados AES, Chacha20, GCM

IKEv2 500/udp es puerto se utiliza para el intercambio de mensajes de protocolo IKE durante la fase de establecimiento del túnel VPN.
IpSec 4500/udp, establecido el túnel VPN, encapsula y transmite el tráfico de datos IP que  envía a través de la VPN

Características de IPSec
Protección antirreproducción: IPSec asigna un número único a cada paquete cuando se detecta un paquete con un número de secuencia duplicado, luego se reproduce y se descarta.
Autenticación de datos: el código de autenticación de mensajes basado en hash (HMAC) verifica que los paquetes no se modifiquen.
Transparencia: IPSec funciona debajo de la capa de transporte, por lo que es transparente para los usuarios y las aplicaciones.
Confidencialidad: el remitente cifra los paquetes de datos antes de su transmisión, de modo que los datos confidenciales solo lleguen al destinatario previsto.
Recodificación dinámica de claves: el procedimiento de recodificación de claves a intervalos establecidos reemplaza la reconfiguración manual de claves secretas.

ATAQUES:

Ataques de sniffing; MiTM, para mitigarlos utilizaremos claves de cifado fuertes, combinaciones seguras de cifrado, red segura,  actualizado el software.

Ataque Bleichenbacher El proceso de ataque implica llenar intencionalmente un mensaje codificado con errores y luego enviarlo repetidamente al servidor. En casos habituales, la respuesta del servidor contendrá pistas sobre el contenido de la información cifrada y el hacker puede estudiar las respuestas con cada envío del mensaje lleno de errores. De esta manera, el hacker puede estudiar la información basada en las respuestas y obtener inteligencia cada vez más precisa sobre todo el contenido de los datos cifrados.

Ataques IKEv1, extraccion de información (  IKEv1 Heartbleed ), permite interceptar claves precompartidas (PSK) y credenciales de usuario, durante el proceso de establecimiento de un túnel VPN IPsec.

Ataques de suplantación de identidad: Suplantación de IP,Suplantación de DNS, Suplantación de MAC Address, 

Ataques de autenticación fuerza bruta: Fuerza bruta inversa.

Ataques de TCP Replay repetición: Reaplay, reenvío paquetes de autenticación válidos para obtener acceso no autorizado a la VPN.

Ataques Dos: Ataques Dos (Denegacion de servicio), Inundacion paquetes UDP, puertos 500/4500, IKE de autenticación. Ataques de inundacion con paquetes y trafico. Ataques Los ataques de fragmentación aprovechan la forma en que IPSec fragmenta los paquetes de datos para enviar fragmentos mal formados al servidor VPN. Esto puede hacer que el servidor se bloquee o se reinicie.  Puertos/servicios:

# Cliente Pulse VPN para Linux
cliente VPN pulsesecure en bash shell Linux

./pulse.sh

# http://www.hackingyseguridad.com
