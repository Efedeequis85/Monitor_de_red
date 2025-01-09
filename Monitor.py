from scapy.all import *

def visualizar(log):
        print(f'{log['IP_DST']}')

def leer_paquete(p):
        print(p)
        log = {
                "MAC_SRC":     p['Ether'].src,
                "MAC_DST":     p['Ether'].dst,
                "IP_SRC":      p['IP'].src,
                "IP_DST":      p['IP'].dst,
                "PROTOCOLO":   p['TCP'].dport
        }
        logs.append(log)
        visualizar(log)

logs = []
red = 'wlo1'
filtros = 'tcp'
salida = 'log.pcap'

print(red, filtros, salida)

try:
        sniff(prn=leer_paquete, iface=red, filter=filtros, count=10)
except KeyboardInterrupt:
        print('Finalizado')
        print(salida + ' Generado.')
