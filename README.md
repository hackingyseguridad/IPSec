# IPSec

IPSec es un protocolo diseñado para poder conectar clientes en una RPV, redes privadasd virtuales, y aplicar cifrados, control de integridad a los datos y autenticacin; IPsec es un  protocolo de nivel de enlace que proporcina seguridad, Capa 3, estandarizado para Ipv4, IPv6.

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

AH y/o ESP son los dos protocolos que utilizamos para proteger los datos del usuario. Ambos se pueden utilizar en modo transporte o túne

Dos posibles modos de uso; trasportel y tunel:

Trasporte, es cabecera AH, 

Tunel, se le etuqeta con IP origen y destino a todo el paquete IP`+AH.

La  diferencia entre los dos es que con el modo de transporte usaremos el encabezado IP original mientras que en el modo túnel usaremos un nuevo encabezado IP . 

IKEv2 admite la autenticación EAP (claves precompartida y certificado digital).  tiene soporte integrado para cruce NAT


ataques de sniffing
PSec se puede piratear mediante un método llamado ataque Bleichenbacher. Investigadores del Instituto Horst Görtz de Seguridad TI en Alemania y la Universidad de Opole en Polonia demostraron por primera vez que el método tiene éxito al

El proceso de ataque implica llenar intencionalmente un mensaje codificado con errores y luego enviarlo repetidamente al servidor. En casos habituales, la respuesta del servidor contendrá pistas sobre el contenido de la información cifrada y el hacker puede estudiar las respuestas con cada envío del mensaje lleno de errores. De esta manera, el hacker puede estudiar la información basada en las respuestas y obtener inteligencia cada vez más precisa sobre todo el contenido de los datos cifrados.

¿Cuáles son los aspectos históricos de IPSec?
Una imagen que presenta IPsec y el concepto de servidores.
Internet comenzó siendo pequeño y la seguridad no era una preocupación a principios de la década de 1980, ya que solo había unas pocas docenas de máquinas conectadas. Cuando se estableció Internet, la seguridad era mucho más fácil para las organizaciones y los investigadores con la simple implementación de cerraduras físicas y sistemas de seguridad para evitar que alguien husmeara en información confidencial. Sin embargo, Internet creció rápidamente a principios de la década de 2000. Con este rápido crecimiento en popularidad, la seguridad de las redes de Internet también se disipó con el tiempo, ya que simplemente colocar un sistema de seguridad físico para proteger el hardware que contenía información ya no era suficiente. Los piratas informáticos pueden ejecutar operaciones de forma remota sin tener que ir al sitio físico.

Para abordar esta necesidad de seguridad, la Agencia de Seguridad Nacional de Estados Unidos patrocinó el desarrollo de protocolos de seguridad a mediados de los años 1980. El Grupo de Trabajo de Ingeniería de Internet encabezó el proyecto y desarrolló aún más los protocolos que ahora se sabe que componen todo el conjunto de protocolos IPSec.
¿Cuál es la diferencia entre el modo de túnel IPSec y el modo de transporte IPSec?
La principal diferencia entre el modo de túnel IPSec y el modo de transporte IPSec es que el modo de túnel se refiere a la tunelización o conexión de dos hosts, y ciertas configuraciones de este modo crean una capa adicional de encabezados para cifrar. Estos encabezados incluyen información para los enrutadores intermediarios sobre dónde reenviar los paquetes. En cada extremo del túnel, los paquetes intercambiados se descifran para que puedan llegar a los destinos asignados.

En el modo de transporte, por otro lado, los enrutadores intermediarios pueden acceder a la información dentro del encabezado sin descifrarla, excepto la carga útil.

¿Cuál es la diferencia entre VPN IPSec y VPN SSL?
Una imagen que muestra a una persona señalando el concepto de servicio VPN.
Una VPN IPSec es el enfoque más tradicional para proteger la privacidad en Internet, mientras que una VPN SSL se desarrolló recientemente, tras la introducción de servicios basados ​​en la nube. La principal diferencia radica en cómo opera cada tecnología y la complejidad de configurar la VPN.

Las VPN IPSec son generalmente más complicadas ya que los usuarios deben instalar software cliente de terceros. Las VPN SSL, por otro lado, ya son compatibles con los navegadores. Estos dos tipos de VPN operan en diferentes capas del modelo de red OSI. Las VPN IPSec funcionan dentro de la capa de red del modelo OSI, mientras que SSL funciona en la capa de aplicación del modelo.

https://harrymaq.medium.com/what-is-ipsec-how-does-it-works-what-are-its-phases-and-modes-965b5523727c
https://www.linkedin.com/pulse/asegura-tus-comunicaciones-iot-con-vpn-y-olv%C3%ADdate-de-los-joel-benitez/


# Cliente Pulse VPN para Linux
cliente VPN pulsesecure en bash shell Linux
