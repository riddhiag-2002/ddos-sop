import time
from hash_table_ddos import HashTableDDoS
from bloom_filter_ddos import BloomFilterDDoS
from multops_ddos import MULTOPS
from hybrid_ddos_adaptive import AdaptiveHybridDDoS
from hybrid_ddos_burst import BurstDetectionHybridDDoS
from traffic_generator import TrafficGenerator

def run_test(detector, traffic, duration):
    start_time = time.time()
    detections = 0
    packets_processed = 0
    
    print(f"Starting test for {duration} seconds...")
    for ip in traffic.generate_traffic(duration=duration):
        is_ddos, _ = detector.process_packet(ip)
        if is_ddos:
            detections += 1
        packets_processed += 1
        
        if packets_processed % 1000 == 0:
            print(f"Processed {packets_processed} packets, {detections} detections so far...")
        
        if time.time() - start_time >= duration:
            break
    
    print(f"Test completed. Processed {packets_processed} packets, detected {detections} DDoS attempts.")
    return detections, packets_processed

def compare_detectors(duration=60, packets_per_second=1000):
    print(f"Starting comparison with duration={duration}s, packets_per_second={packets_per_second}")
    traffic = TrafficGenerator()
    detectors = [
        ("Hash Table", HashTableDDoS()),
        ("Bloom Filter", BloomFilterDDoS()),
        ("MULTOPS", MULTOPS()),
        ("Adaptive Hybrid", AdaptiveHybridDDoS()),
        ("Burst Detection Hybrid", BurstDetectionHybridDDoS())
    ]
    
    results = {}
    
    for name, detector in detectors:
        print(f"\nTesting {name}...")
        print("-" * 40)
        detections, packets_processed = run_test(detector, traffic, duration)
        results[name] = {
            "detections": detections,
            "packets_processed": packets_processed,
            "detection_rate": detections / packets_processed if packets_processed > 0 else 0
        }
        detector.reset()
        print(f"{name} test completed.")
        print("-" * 40)
    
    print("\nFinal Results:")
    print("=" * 50)
    for name, data in results.items():
        print(f"{name}:")
        print(f"  Detections: {data['detections']}")
        print(f"  Packets Processed: {data['packets_processed']}")
        print(f"  Detection Rate: {data['detection_rate']:.4f}")
        print("-" * 50)

if __name__ == "__main__":
    print("Starting DDoS detection comparison...")
    compare_detectors(duration=60, packets_per_second=10000)
    print("Comparison completed.")
