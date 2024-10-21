import mmh3
import time
from bitarray import bitarray
from collections import deque

class BloomFilterDDoS:
    def __init__(self, size=10000, hash_count=5, window_size=60, rate_limit=100):
        self.size = size
        self.hash_count = hash_count
        self.bit_array = bitarray(size)
        self.bit_array.setall(0)
        self.packet_count = 0
        self.window_size = window_size  # Time window in seconds
        self.rate_limit = rate_limit  # Max packets per IP in the time window
        self.ip_timestamps = {}

    def add(self, item):
        for i in range(self.hash_count):
            index = mmh3.hash(item, i) % self.size
            self.bit_array[index] = 1

    def check(self, item):
        for i in range(self.hash_count):
            index = mmh3.hash(item, i) % self.size
            if not self.bit_array[index]:
                return False
        return True

    def process_packet(self, ip_address):
        current_time = time.time()
        self.packet_count += 1

        if not self.check(ip_address):
            self.add(ip_address)
            self.ip_timestamps[ip_address] = deque([current_time], maxlen=self.rate_limit + 1)
            return False, self.packet_count
        else:
            timestamps = self.ip_timestamps.get(ip_address)
            if timestamps is None:
                timestamps = deque(maxlen=self.rate_limit + 1)
                self.ip_timestamps[ip_address] = timestamps
            
            while timestamps and current_time - timestamps[0] > self.window_size:
                timestamps.popleft()
            
            timestamps.append(current_time)
            
            is_ddos = len(timestamps) > self.rate_limit
            return is_ddos, self.packet_count

    def reset(self):
        self.bit_array.setall(0)
        self.packet_count = 0
        self.ip_timestamps.clear()

if __name__ == "__main__":
    detector = BloomFilterDDoS()
    
    # Simple test
    test_ips = ["192.168.1.1"] * 50 + ["192.168.1.2"] * 150
    for ip in test_ips:
        is_ddos, message = detector.process_packet(ip)
        if is_ddos:
            print(message)
        time.sleep(0.01)
