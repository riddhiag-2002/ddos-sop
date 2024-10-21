import time

class Node:
    def __init__(self):
        self.incoming = 0
        self.outgoing = 0
        self.children = {}

class MULTOPS:
    def __init__(self, threshold_ratio=2, expansion_threshold=1000):
        self.root = Node()
        self.threshold_ratio = threshold_ratio
        self.expansion_threshold = expansion_threshold

    def update(self, ip, is_incoming):
        node = self.root
        for i in range(0, 32, 8):  # Traverse the IP address in 8-bit chunks
            prefix = ip >> (24 - i)
            if prefix not in node.children:
                node.children[prefix] = Node()
            node = node.children[prefix]
            
            if is_incoming:
                node.incoming += 1
            else:
                node.outgoing += 1
            
            if max(node.incoming, node.outgoing) > self.expansion_threshold:
                break

    def process_packet(self, ip_address, is_incoming=True):
        ip_int = int(''.join([bin(int(x)+256)[3:] for x in ip_address.split('.')]), 2)
        self.update(ip_int, is_incoming)
        
        node = self.root
        is_ddos = False
        ratio = 0
        
        for i in range(0, 32, 8):
            prefix = ip_int >> (24 - i)
            if prefix not in node.children:
                break
            node = node.children[prefix]
            
            if node.outgoing > 0:
                ratio = node.incoming / node.outgoing
            else:
                ratio = node.incoming
            
            if ratio > self.threshold_ratio and node.incoming > self.expansion_threshold:
                is_ddos = True
                break

        return is_ddos, ratio

    def reset(self):
        self.root = Node()

if __name__ == "__main__":
    detector = MULTOPS(threshold_ratio=3, expansion_threshold=50)
    
    # More realistic test
    test_data = (["192.168.1.1"] * 5 + ["192.168.1.2"] * 15) * 10  # Incoming
    test_data += (["192.168.1.1"] * 2 + ["192.168.1.2"] * 3) * 10  # Outgoing
    
    for ip in test_data:
        is_incoming = test_data.index(ip) < len(test_data) // 2
        is_ddos, ratio = detector.process_packet(ip, is_incoming)
        if is_ddos:
            print(f"Potential DDoS detected for prefix {ip} (ratio {ratio:.2f})")
        time.sleep(0.01)
