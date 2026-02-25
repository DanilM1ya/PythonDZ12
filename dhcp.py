import pyshark
import pandas as pd
import matplotlib.pyplot as plt
from collections import Counter
import asyncio

try:
    loop = asyncio.get_event_loop()
except:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

print("АНАЛИЗ DHCP ТРАФИКА")

#1. Загрузка
print("\n[1] Загрузка dhcp.pcapng")
cap = pyshark.FileCapture('dhcp.pcapng')

#2. Сбор данных
print("[2] Сбор артефактов")
data = []

for pkt in cap:
    if hasattr(pkt, 'dhcp'):
        info = {
            'time': pkt.sniff_time,
            'src_mac': pkt.eth.src if hasattr(pkt, 'eth') else 'unknown',
            'dst_mac': pkt.eth.dst if hasattr(pkt, 'eth') else 'unknown',
            'type': 'unknown',
            'client_ip': '0.0.0.0',
            'server_ip': '0.0.0.0'
        }
        
        #Тип DHCP
        if hasattr(pkt.dhcp, 'option_dhcp_message_type'):
            msg = pkt.dhcp.option_dhcp_message_type
            types = {
                '1': 'DISCOVER',
                '2': 'OFFER', 
                '3': 'REQUEST',
                '4': 'DECLINE',
                '5': 'ACK',
                '6': 'NAK'
            }
            info['type'] = types.get(msg, f'UNKNOWN_{msg}')
        
        #IP адреса
        if hasattr(pkt.dhcp, 'option_requested_ip_address'):
            info['client_ip'] = pkt.dhcp.option_requested_ip_address
        if hasattr(pkt.dhcp, 'option_dhcp_server_identifier'):
            info['server_ip'] = pkt.dhcp.option_dhcp_server_identifier
        
        data.append(info)

cap.close()
df = pd.DataFrame(data)
print(f"Найдено DHCP пакетов: {len(df)}")

if len(df) == 0:
    print("Нет DHCP пакетов!")
    exit()

#3. Анализ
print("\n[3] Анализ данных:")

#Типы запросов
print("\nТипы запросов")
types_count = Counter(df['type'])
for t, c in types_count.most_common():
    print(f"  {t}: {c}")

#MAC адреса
print("\nMAC адреса")
for mac in df['src_mac'].unique():
    count = len(df[df['src_mac'] == mac])
    print(f"  {mac}: {count} пакетов")

#IP адреса
print("\nIP адреса")
clients = df[df['client_ip'] != '0.0.0.0']['client_ip'].unique()
servers = df[df['server_ip'] != '0.0.0.0']['server_ip'].unique()
print(f"  Клиенты: {clients}")
print(f"  Серверы: {servers}")

#4. Визуализация
print("\n[4] Рисуем графики")

plt.figure(figsize=(14, 8))

#График 1: Типы DHCP запросов
plt.subplot(2, 2, 1)
plt.bar(types_count.keys(), types_count.values(), color='skyblue')
plt.title('Типы DHCP запросов')
plt.xticks(rotation=45)

#График 2:Топ-5 MAC адресов
plt.subplot(2, 2, 2)
mac_counts = df['src_mac'].value_counts().head(5)
plt.bar(range(len(mac_counts)), mac_counts.values, color='lightgreen')
plt.xticks(range(len(mac_counts)), [m[:8] for m in mac_counts.index], rotation=45)
plt.title('Топ-5 MAC адресов')

#График 3: Активность по времени
plt.subplot(2, 1, 2)
df['time'] = pd.to_datetime(df['time'])
df['min'] = df['time'].dt.floor('min')
time_stats = df.groupby('min').size()
if len(time_stats) > 0:
    plt.plot(time_stats.index, time_stats.values, marker='o', color='red')
    plt.title('Активность по времени')
    plt.grid(True)

plt.tight_layout()
plt.savefig('dhcp_graf.png', dpi=150)
plt.show()

#5. Сохраняем
df.to_csv('dhcp_data.csv', index=False)
print("\n[5] Сохранено: dhcp_graf.png, dhcp_data.csv")

#6. Поиск аномалий
print("\n[6] Поиск аномалий:")

#Много запросов
for mac, count in df['src_mac'].value_counts().items():
    if count > 5:
        print(f" Много запросов ({count}) от {mac[:8]}")

#Необычные типы
unusual = df[~df['type'].isin(['DISCOVER', 'REQUEST', 'ACK', 'OFFER'])]
if len(unusual) > 0:
    print(f"  Необычные типы: {unusual['type'].unique()}")

if len(df[df['client_ip'] != '0.0.0.0']) > 0:
    print(f" Найдены выданные IP")

print("ГОТОВО!")