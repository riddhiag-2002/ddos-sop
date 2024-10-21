import time
from collections import defaultdict

class HashTableDDoS:
    def __init__(self, threshold=100, time_window=60, decay_factor=0.5):
        self.threshold = threshold
        self.time_window = time_window
        self.decay_factor = decay_factor
        self.request_table = defaultdict(lambda: {"count": 0, "first_request_time": None})

    def process_packet(self, ip_address):
        current_time = time.time()
        
        if self.request_table[ip_address]["first_request_time"] is None:
            self.request_table[ip_address]["first_request_time"] = current_time
        
        # Decay the request count over time
        elapsed_time = current_time - self.request_table[ip_address]["first_request_time"]
        self.request_table[ip_address]["count"] *= self.decay_factor ** (elapsed_time / self.time_window)
        self.request_table[ip_address]["first_request_time"] = current_time
        
        self.request_table[ip_address]["count"] += 1
        
        # Detect potential DDoS attack
        is_ddos = self.request_table[ip_address]["count"] > self.threshold
        return is_ddos, self.request_table[ip_address]["count"]

    def reset(self):
        self.request_table.clear()

if __name__ == "__main__":
    detector = HashTableDDoS()
    
    # Simple test
    test_ips = ["192.168.1.1"] * 50 + ["192.168.1.2"] * 150
    for ip in test_ips:
        is_ddos, message = detector.process_packet(ip)
        if is_ddos:
            print(message)
        time.sleep(0.01)
