# entity.py - Player entity management with anti-detection measures
from offsets import Offsets
from vector import Vector3
import random
import time

class PlayerCache:
    """Cache for player data to reduce memory reads"""
    
    def __init__(self):
        self.cache = {}
        self.last_cleanup = time.time()
        self.cleanup_interval = random.uniform(10, 20)  # Clean cache every 10-20 seconds
    
    def get(self, key, default=None):
        """Get value from cache with expiration check"""
        if key in self.cache:
            entry = self.cache[key]
            if time.time() - entry['time'] < entry['ttl']:
                return entry['value']
            else:
                # Expired
                del self.cache[key]
        return default
    
    def set(self, key, value, ttl=None):
        """Set value in cache with TTL"""
        if ttl is None:
            # Random TTL between 0.5 and 2 seconds
            ttl = random.uniform(0.5, 2.0)
            
        self.cache[key] = {
            'value': value,
            'time': time.time(),
            'ttl': ttl
        }
    
    def cleanup(self):
        """Remove expired entries from cache"""
        current_time = time.time()
        
        # Only clean up at intervals
        if current_time - self.last_cleanup < self.cleanup_interval:
            return
            
        self.last_cleanup = current_time
        
        # Set new random cleanup interval
        self.cleanup_interval = random.uniform(10, 20)
        
        # Remove expired entries
        expired_keys = []
        for key, entry in self.cache.items():
            if current_time - entry['time'] >= entry['ttl']:
                expired_keys.append(key)
                
        for key in expired_keys:
            del self.cache[key]

# Global cache instance
player_cache = PlayerCache()

class Player:
    def __init__(self, memory, base_address):
        self.memory = memory
        self.base_address = base_address
        self.position = Vector3(0, 0, 0)
        self.eye_position = Vector3(0, 0, 0)
        self.head_position = Vector3(0, 0, 0)
        self.health = 0
        self.team = 0
        self.last_update = 0
        self.update_interval = random.uniform(0.05, 0.15)  # Update every 50-150ms
        self.cache_key = f"player_{base_address}"
        self.update()
        
    def update(self):
        """Update player data from memory with anti-detection measures"""
        current_time = time.time()
        
        # Only update at intervals to reduce memory reads
        if current_time - self.last_update < self.update_interval:
            return
            
        self.last_update = current_time
        
        # Set new random update interval
        self.update_interval = random.uniform(0.05, 0.15)
        
        try:
            # Check cache first
            cached_data = player_cache.get(self.cache_key)
            if cached_data:
                self.health = cached_data['health']
                self.team = cached_data['team']
                self.position = cached_data['position']
                self.eye_position = cached_data['eye_position']
                self.head_position = cached_data['head_position']
                return
                
            # Randomize read order to avoid detection patterns
            read_order = ['health', 'team', 'position', 'view_offset', 'head']
            random.shuffle(read_order)
            
            data = {}
            
            for attribute in read_order:
                # Add small random delay between reads
                if random.random() < 0.1:  # 10% chance
                    time.sleep(random.uniform(0.0001, 0.0005))
                    
                if attribute == 'health':
                    self.health = self.memory.read_int(self.base_address + Offsets.m_iHealth)
                    data['health'] = self.health
                elif attribute == 'team':
                    self.team = self.memory.read_int(self.base_address + Offsets.m_iTeam)
                    data['team'] = self.team
                elif attribute == 'position':
                    # Get position (feet)
                    x = self.memory.read_float(self.base_address + Offsets.m_vecOrigin)
                    y = self.memory.read_float(self.base_address + Offsets.m_vecOrigin + 4)
                    z = self.memory.read_float(self.base_address + Offsets.m_vecOrigin + 8)
                    self.position = Vector3(x, y, z)
                    data['position'] = self.position
                elif attribute == 'view_offset':
                    # Get eye position (feet + view offset)
                    view_offset_x = self.memory.read_float(self.base_address + Offsets.m_vecViewOffset)
                    view_offset_y = self.memory.read_float(self.base_address + Offsets.m_vecViewOffset + 4)
                    view_offset_z = self.memory.read_float(self.base_address + Offsets.m_vecViewOffset + 8)
                    self.eye_position = Vector3(
                        self.position.x + view_offset_x,
                        self.position.y + view_offset_y,
                        self.position.z + view_offset_z
                    )
                    data['eye_position'] = self.eye_position
                elif attribute == 'head':
                    # Get head position from bone matrix
                    self.head_position = self.get_bone_position(Offsets.BONE_HEAD)
                    data['head_position'] = self.head_position
            
            # Debug output for player data
            print(f"Player data updated: Health={self.health}, Team={self.team}, Position={self.position}")
            
            # Cache the data
            player_cache.set(self.cache_key, data)
            
            # Clean up cache occasionally
            player_cache.cleanup()
            
        except Exception:
            # Silent fail - this is common when players disconnect or memory changes
            pass
    
    def get_bone_position(self, bone_id):
        """Get position of specific bone from bone matrix with anti-detection measures"""
        # Check cache first
        cache_key = f"{self.cache_key}_bone_{bone_id}"
        cached_position = player_cache.get(cache_key)
        if cached_position:
            return cached_position
            
        try:
            # Add small random delay
            if random.random() < 0.05:  # 5% chance
                time.sleep(random.uniform(0.0001, 0.0005))
                
            bone_matrix_ptr = self.memory.read_int(self.base_address + Offsets.m_dwBoneMatrix)
            
            if bone_matrix_ptr:
                # Randomize read order
                offsets = [(0x0C, 0), (0x1C, 0), (0x2C, 0)]
                random.shuffle(offsets)
                
                bone_pos = [0, 0, 0]  # x, y, z
                
                for i, (offset, index) in enumerate(offsets):
                    bone_pos[index] = self.memory.read_float(bone_matrix_ptr + 0x30 * bone_id + offset)
                    
                    # Add small random delay between reads
                    if random.random() < 0.1 and i < 2:  # 10% chance, skip last read
                        time.sleep(random.uniform(0.0001, 0.0003))
                
                position = Vector3(bone_pos[0], bone_pos[1], bone_pos[2])
                
                # Cache the result
                player_cache.set(cache_key, position, ttl=random.uniform(0.2, 0.5))
                
                return position
            
            return self.position  # Fallback to body position
            
        except Exception:
            return self.position  # Fallback to body position
    
    def is_valid(self):
        """Check if player is valid target with anti-detection measures"""
        # Add occasional random delay
        if random.random() < 0.02:  # 2% chance
            time.sleep(random.uniform(0.0001, 0.0005))
            
        # Occasionally update player data
        if random.random() < 0.1:  # 10% chance
            self.update()
            
        is_valid = self.health > 0 and self.base_address != 0
        
        # Debug output for player validation
        if is_valid:
            print(f"Valid player found: Health={self.health}, Team={self.team}")
            
        return is_valid
        
    def is_enemy(self, local_team):
        """Check if player is enemy with anti-detection measures"""
        # Add occasional random delay
        if random.random() < 0.02:  # 2% chance
            time.sleep(random.uniform(0.0001, 0.0005))
            
        # Occasionally update player data
        if random.random() < 0.05:  # 5% chance
            self.update()
            
        is_enemy = self.team != local_team and self.team in [1, 2]  # 1=T, 2=CT
        
        # Debug output for enemy detection
        if is_enemy:
            print(f"Enemy player found: Team={self.team}, Local Team={local_team}")
            
        return is_enemy
