import pyshark
import pandas as pd

capture = pyshark.FileCapture("../data/traffic.pcapng")

features = []

for packet in capture:
    try:
        row = {
            "Protocol": packet.highest_layer,
            "Length": int(packet.length),
            "Source_IP": packet.ip.src if hasattr(packet, "ip") else "Unknown",
            "Destination_IP": packet.ip.dst if hasattr(packet, "ip") else "Unknown"
        }

        if hasattr(packet, "tcp"):
            row["Source_Port"] = packet.tcp.srcport
            row["Destination_Port"] = packet.tcp.dstport

        elif hasattr(packet, "udp"):
            row["Source_Port"] = packet.udp.srcport
            row["Destination_Port"] = packet.udp.dstport

        else:
            row["Source_Port"] = 0
            row["Destination_Port"] = 0

        features.append(row)

    except Exception:
        continue

capture.close()

df = pd.DataFrame(features)

df.to_csv("../output/network_features.csv", index=False)

print("===================================")
print(" NETWORK TRAFFIC FEATURE EXTRACTION")
print("===================================")

print("Total Packets:", len(df))

print("\nExtracted Features:")
print(df.head())

print("\nProtocol Distribution:")
print(df["Protocol"].value_counts())

print("\nFeature extraction completed!")
print("CSV saved as: output/network_features.csv")