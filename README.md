# IPSec

IPSec es un protocolo diseñado para poder conectar clientes en una RPV, redes privadasd virtuales, y aplicar cifrados, control de integridad a los datos y autenticacin; IPsec es un  protocolo de nivel de enlace que proporcina seguridad, Capa 3, estandarizado para Ipv4, IPv6.

Se establecen dos tuneles por fases:

Fase 1:

IKE ( autenticación )  

Fase 2:

AH (Cabecera adicional IP, para control integridad, calcula un HASH y MAC clave simetrica, para comprobar en destino), 
ESP (Cifrado, es una etiqueta, encabezado y cola sobre el paquete IP +AH)

Dos posibles modos de uso; trasportel y tunel:

Trasporte, es cabecera AH, 

Tunel, se le etuqeta con IP origen y destino a todo el paquete IP`+AH.



https://harrymaq.medium.com/what-is-ipsec-how-does-it-works-what-are-its-phases-and-modes-965b5523727c



# Cliente Pulse VPN para Linux
cliente VPN pulsesecure en bash shell Linux
