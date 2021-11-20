'''
Meta->Descubrir clientes en la Red

Pasos:
1. Crear solicitud arp y direccionarlo a broadcast mac preguntando por ip
    dos partes principales:
        -> Usar arp y preguntar quien tiene esa ip o target-ip
        -> Fijar el destino de la mac
2. Enviar paquetes y recibir respuestas
3. Analizar la respuestas
4. mostrar resultado

Nota: Para enviar datos utilizamos la mac no la ip

###[ Ethernet ]###
  dst       = ff:ff:ff:ff:ff:ff <--(destino)
  src       = 28:c6:3f:41:40:fb <--- esta es mi mac (fuente)
  type      = ARP
'''
import scapy.all as scapy
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP range.")
    options = parser.parse_args()
    return options

def scan(ip):
    #1.{#####################
    arp_request = scapy.ARP(pdst=ip)# Aqui creamos la solicitud de preguntar quien tiene esa direcciion el cual le damos como parametro un rango de ip's
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")#Aqui fijamos nuestro mac #step 2 
    arp_request_broadcast = broadcast/arp_request#combinanos los dos paquetes dentro de un paquete
    #print(arp_request_broadcast.summary())
    #####################}
    #2.{#################
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]#Verbose no muestra tan detallado, en otras palabras nos quita el begin y los datos que fueron mandado,timeout es un tiempo de espera ásicamente, cuando establecemos un tiempo de espera, estamos diciendo que espere esta cantidad de segundos. Si no obtiene ninguna respuesta, continúe, no siga esperando.
    #print(answered_list)
    ####################}
    clients_list = []
    for element in answered_list:
        #print(element)
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}#Creamos un diccionaro en el cual accedemos a la lista de respuesta y a los atributos arp con .
        clients_list.append(client_dict)
    return clients_list

def print_result(results_list):
    print("IP\t\t\tMAC Address\n-------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])#Acedemos a los datos del diccionario


options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)