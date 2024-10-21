from hash_table_ddos import HashTableDDoS
from bloom_filter_ddos import BloomFilterDDoS
from multops_ddos import MULTOPS
import time

class AdaptiveHybridDDoS:
    def __init__(self):
        self.hash_table = AdaptiveHashTableDDoS(threshold=80, time_window=30, decay_factor=0.7)
        self.bloom_filter = BloomFilterDDoS(size=100000, hash_count=7)
        self.multops = MULTOPS(threshold_ratio=3, expansion_threshold=500)

    def process_packet(self, ip_address):
        # First, check the Bloom filter for quick filtering
        bf_is_ddos, bf_count = self.bloom_filter.process_packet(ip_address)
        
        if bf_is_ddos:
            # If Bloom filter indicates potential DDoS, check with adaptive hash table for confirmation
            ht_is_ddos, ht_count, ht_window = self.hash_table.process_packet(ip_address)
            
            if ht_is_ddos:
                # If both Bloom filter and hash table indicate DDoS, use MULTOPS for final verification
                multops_is_ddos, multops_ratio = self.multops.process_packet(ip_address)
                
                if multops_is_ddos:
                    return True, f"DDoS detected: BF({bf_count}), HT({ht_count}, {ht_window:.2f}s), MULTOPS({multops_ratio:.2f})"
                else:
                    return False, f"Potential DDoS: BF({bf_count}), HT({ht_count}, {ht_window:.2f}s), MULTOPS({multops_ratio:.2f})"
            else:
                return False, f"Suspicious: BF({bf_count}), HT({ht_count}, {ht_window:.2f}s)"
        else:
            # If Bloom filter doesn't indicate DDoS, still update hash table and MULTOPS
            _, ht_count, ht_window = self.hash_table.process_packet(ip_address)
            self.multops.process_packet(ip_address)
            return False, f"Normal traffic: BF({bf_count}), HT({ht_count}, {ht_window:.2f}s)"

    def reset(self):
        self.hash_table.reset()
        self.bloom_filter.reset()
        self.multops.reset()

class AdaptiveHashTableDDoS:
    def __init__(self, threshold=100, time_window=60, decay_factor=0.5):
        self.threshold = threshold
        self.default_time_window = time_window
        self.min_time_window = 10
        self.decay_factor = decay_factor
        self.request_table = {}

    def process_packet(self, ip_address):
        current_time = time.time()
        
        if ip_address not in self.request_table:
            self.request_table[ip_address] = {
                "count": 0,
                "first_request_time": current_time,
                "time_window": self.default_time_window
            }
        
        self.request_table[ip_address]["count"] += 1
        elapsed_time = current_time - self.request_table[ip_address]["first_request_time"]
        
        # Adjust time window if close to threshold
        if self.request_table[ip_address]["count"] > self.threshold * 0.8:
            self.request_table[ip_address]["time_window"] = max(
                self.min_time_window, 
                self.request_table[ip_address]["time_window"] - 5
            )
        
        # Check if time window expired
        if elapsed_time > self.request_table[ip_address]["time_window"]:
            self.request_table[ip_address]["count"] *= self.decay_factor ** (elapsed_time / self.request_table[ip_address]["time_window"])
            self.request_table[ip_address]["first_request_time"] = current_time
            self.request_table[ip_address]["time_window"] = min(
                self.default_time_window,
                self.request_table[ip_address]["time_window"] + 5
            )
        
        # Detect potential DDoS attack
        is_ddos = self.request_table[ip_address]["count"] > self.threshold
        if is_ddos:
            self.request_table[ip_address]["time_window"] = self.min_time_window  # Minimize the window for quick re-evaluation
        
        return is_ddos, self.request_table[ip_address]["count"], self.request_table[ip_address]["time_window"]

    def reset(self):
        self.request_table.clear()
