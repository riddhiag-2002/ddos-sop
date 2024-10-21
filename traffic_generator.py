import random
import time

class TrafficGenerator:
    def __init__(self, normal_ips=100, attack_ips=10, attack_rate=5):
        self.normal_ips = [f"192.168.1.{i}" for i in range(normal_ips)]
        self.attack_ips = [f"10.0.0.{i}" for i in range(attack_ips)]
        self.attack_rate = attack_rate

    def generate_traffic(self, duration=60, packets_per_second=1000):
        start_time = time.time()
        while time.time() - start_time < duration:
            for _ in range(packets_per_second):
                if random.random() < 0.8:  # 80% normal traffic
                    yield random.choice(self.normal_ips)
                else:  # 20% potential attack traffic
                    for _ in range(self.attack_rate):
                        yield random.choice(self.attack_ips)
            time.sleep(1)

if __name__ == "__main__":
    generator = TrafficGenerator()
    for ip in generator.generate_traffic(duration=10, packets_per_second=100):
        print(ip)
        time.sleep(0.01)
