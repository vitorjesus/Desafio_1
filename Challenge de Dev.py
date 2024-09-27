from scapy.all import sniff
from collections import Counter

# Variáveis globais para armazenar dados
packet_count = 0
protocol_count = Counter()
src_ip_count = Counter()
dst_ip_count = Counter()

# Função que será chamada para processar cada pacote capturado


def process_packet(packet):
    global packet_count
    packet_count += 1

    # Captura IP de origem e destino
    if packet.haslayer('IP'):
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        protocol = packet['IP'].proto  # Protocolo (ex: TCP, UDP)

        # Contar IPs e protocolos
        src_ip_count[src_ip] += 1
        dst_ip_count[dst_ip] += 1
        protocol_count[protocol] += 1

        print(f"Pacote capturado: {src_ip} -> {dst_ip}, Protocolo: {protocol}")

# Função para capturar pacotes de rede


def capture_traffic(interface, packet_limit):
    print(f"Iniciando captura na interface: {interface}")
    sniff(iface=interface, prn=process_packet, count=packet_limit)

# Função para exibir as estatísticas básicas


def display_statistics():
    print(f"\nTotal de pacotes capturados: {packet_count}")

    # Mostrar contagem de pacotes por protocolo
    print("\nContagem de pacotes por protocolo:")
    for proto, count in protocol_count.items():
        print(f"Protocolo {proto}: {count} pacotes")

    # Mostrar os top 5 IPs de origem e destino
    print("\nTop 5 IPs de origem com mais tráfego:")
    for ip, count in src_ip_count.most_common(5):
        print(f"{ip}: {count} pacotes")

    print("\nTop 5 IPs de destino com mais tráfego:")
    for ip, count in dst_ip_count.most_common(5):
        print(f"{ip}: {count} pacotes")


# Função principal
if __name__ == "__main__":
    # Interface e número de pacotes a serem capturados
    interface = input(
        "Digite a interface de rede para captura (ex: eth0, wlan0): ")
    packet_limit = int(input("Digite o número de pacotes a capturar: "))

    # Iniciar a captura de pacotes
    capture_traffic(interface, packet_limit)

    # Exibir as estatísticas após a captura
    display_statistics()
