from hash_table_ddos import HashTableDDoS
from bloom_filter_ddos import BloomFilterDDoS
from multops_ddos import MULTOPS
import time

class BurstDetectionHybridDDoS:
    def __init__(self):
        self.hash_table = BurstDetectionHashTableDDoS(threshold=80, time_window=30, decay_factor=0.7)
        self.bloom_filter = BloomFilterDDoS(size=100000, hash_count=7)
        self.multops = MULTOPS(threshold_ratio=3, expansion_threshold=500)

    def process_packet(self, ip_address):
        # First, check the Bloom filter for quick filtering
        bf_is_ddos, bf_count = self.bloom_filter.process_packet(ip_address)
        
        if bf_is_ddos:
            # If Bloom filter indicates potential DDoS, check with burst detection hash table for confirmation
            ht_is_ddos, ht_count, is_burst = self.hash_table.process_packet(ip_address)
            
            if ht_is_ddos or is_burst:
                # If either hash table or burst detection indicates DDoS, use MULTOPS for final verification
                multops_is_ddos, multops_ratio = self.multops.process_packet(ip_address)
                
                if multops_is_ddos:
                    return True, f"DDoS detected: BF({bf_count}), HT({ht_count}, Burst:{is_burst}), MULTOPS({multops_ratio:.2f})"
                else:
                    return False, f"Potential DDoS: BF({bf_count}), HT({ht_count}, Burst:{is_burst}), MULTOPS({multops_ratio:.2f})"
            else:
                return False, f"Suspicious: BF({bf_count}), HT({ht_count}, Burst:{is_burst})"
        else:
            # If Bloom filter doesn't indicate DDoS, still update hash table and MULTOPS
            _, ht_count, is_burst = self.hash_table.process_packet(ip_address)
            self.multops.process_packet(ip_address)
            return False, f"Normal traffic: BF({bf_count}), HT({ht_count}, Burst:{is_burst})"

    def reset(self):
        self.hash_table.reset()
        self.bloom_filter.reset()
        self.multops.reset()

class BurstDetectionHashTableDDoS:
    def __init__(self, threshold=100, time_window=60, decay_factor=0.5):
        self.threshold = threshold
        self.time_window = time_window
        self.decay_factor = decay_factor
        self.request_table = {}
        self.burst_threshold = threshold // 2
        self.burst_window = time_window // 6

    def process_packet(self, ip_address):
        current_time = time.time()
        
        if ip_address not in self.request_table:
            self.request_table[ip_address] = {
                "count": 0,
                "first_request_time": current_time,
                "burst_count": 0,
                "last_burst_time": current_time
            }
        
        self.request_table[ip_address]["count"] += 1
        self.request_table[ip_address]["burst_count"] += 1
        elapsed_time = current_time - self.request_table[ip_address]["first_request_time"]
        burst_elapsed_time = current_time - self.request_table[ip_address]["last_burst_time"]
        
        # Decay the request count over time
        self.request_table[ip_address]["count"] *= self.decay_factor ** (elapsed_time / self.time_window)
        self.request_table[ip_address]["first_request_time"] = current_time
        
        # Check for burst
        is_burst = False
        if burst_elapsed_time <= self.burst_window:
            if self.request_table[ip_address]["burst_count"] > self.burst_threshold:
                is_burst = True
        else:
            self.request_table[ip_address]["burst_count"] = 1
            self.request_table[ip_address]["last_burst_time"] = current_time
        
        # Detect potential DDoS attack
        is_ddos = self.request_table[ip_address]["count"] > self.threshold
        
        return is_ddos, self.request_table[ip_address]["count"], is_burst

    def reset(self):
        self.request_table.clear()
