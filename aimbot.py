
# aimbot.py - Core aimbot logic with anti-detection measures
from vector import Vector3, calculate_angle, normalize_angles, calc_fov, angle_to_vector
from offsets import Offsets
import time
import mouse
import random
import math
import numpy as np

class HumanizedAim:
    """Class to handle humanized aiming behavior"""
    
    def __init__(self):
        # Bezier curve control points for mouse movement
        self.control_points = []
        self.current_point = 0
        self.total_points = 0
        self.last_aim_time = 0
        self.aim_delay = 0
        self.micro_movements = []
        
    def generate_bezier_curve(self, start_x, start_y, end_x, end_y, control_points=1):
        """Generate a more direct Bezier curve for mouse movement"""
        # Start and end points
        points = [(start_x, start_y), (end_x, end_y)]
        
        # Generate fewer control points with minimal deviation for more direct movement
        for _ in range(control_points):
            # Random point along the path with minimal deviation
            t = random.uniform(0.4, 0.6)  # Position closer to middle of path
            
            # Linear interpolation between start and end
            x = start_x + t * (end_x - start_x)
            y = start_y + t * (end_y - start_y)
            
            # Add minimal random deviation
            deviation = random.uniform(0.05, 0.15) * max(abs(end_x - start_x), abs(end_y - start_y))
            x += random.uniform(-deviation, deviation)
            y += random.uniform(-deviation, deviation)
            
            points.insert(-1, (x, y))
        
        # Generate points along the Bezier curve
        t_values = np.linspace(0, 1, 10)  # 10 points along the curve
        curve_points = []
        
        for t in t_values:
            # De Casteljau's algorithm for Bezier curve
            temp_points = points.copy()
            while len(temp_points) > 1:
                new_points = []
                for i in range(len(temp_points) - 1):
                    x = (1 - t) * temp_points[i][0] + t * temp_points[i + 1][0]
                    y = (1 - t) * temp_points[i][1] + t * temp_points[i + 1][1]
                    new_points.append((x, y))
                temp_points = new_points
            
            curve_points.append(temp_points[0])
        
        return curve_points
    
    def generate_micro_movements(self):
        """Generate small random movements to simulate human imprecision"""
        self.micro_movements = []
        # Generate 5-10 small random movements
        num_movements = random.randint(5, 10)
        
        for _ in range(num_movements):
            # Small random x,y offsets
            x_offset = random.uniform(-0.05, 0.05)
            y_offset = random.uniform(-0.05, 0.05)
            self.micro_movements.append((x_offset, y_offset))
    
    def prepare_aim_movement(self, current_angles, target_angles, smoothing):
        """Prepare a more direct aim movement from current to target angles"""
        # Reset state
        self.current_point = 0
        
        # Calculate angle differences
        diff_x = target_angles.x - current_angles.x
        diff_y = target_angles.y - current_angles.y
        
        # Apply reduced smoothing for more noticeable movement
        # Multiply by 0.8 to make movement more aggressive
        diff_x /= (smoothing * 0.8)
        diff_y /= (smoothing * 0.8)
        
        # Generate a more direct Bezier curve for the movement
        self.control_points = self.generate_bezier_curve(
            0, 0,  # Start at origin
            diff_y, diff_x,  # End at the angle difference (swapped for mouse movement)
            1  # Use only 1 control point for more direct movement
        )
        
        self.total_points = len(self.control_points)
        
        # Generate micro-movements
        self.generate_micro_movements()
        
        # Add a small random delay before starting to aim (0-50ms)
        self.aim_delay = random.uniform(0, 0.05)
        self.last_aim_time = time.time()
        
    def get_next_movement(self):
        """Get the next movement in the sequence"""
        if time.time() - self.last_aim_time < self.aim_delay:
            return None  # Still waiting for delay
            
        if self.current_point >= self.total_points:
            return None  # No more points
            
        # Get the next point on the curve
        point = self.control_points[self.current_point]
        self.current_point += 1
        
        # Add micro-movement if available
        if self.micro_movements:
            micro_idx = self.current_point % len(self.micro_movements)
            micro_x, micro_y = self.micro_movements[micro_idx]
            point = (point[0] + micro_x, point[1] + micro_y)
        
        return point
    
    def is_movement_complete(self):
        """Check if the movement sequence is complete"""
        return self.current_point >= self.total_points

class Aimbot:
    def __init__(self, memory_manager, config):
        self.memory = memory_manager
        self.config = config
        self.is_active = False
        self.target_lock = None
        self.last_target_check = 0
        self.view_angles_address = 0
        self.humanized_aim = HumanizedAim()
        self.last_aim_time = 0
        self.aim_cooldown = random.uniform(0.1, 0.3)  # Random cooldown between aims
        self.target_switch_delay = 0  # Delay before switching targets
        self.last_target_id = 0  # Last targeted player ID
        self.consecutive_aims = 0  # Count consecutive aims at same target
        self.max_consecutive_aims = random.randint(3, 7)  # Max consecutive aims before forced break
        self.forced_break_time = 0  # Time when forced break ends
        
    def toggle(self):
        """Toggle aimbot on/off"""
        self.is_active = not self.is_active
        self.target_lock = None  # Reset target lock when toggling
        self.humanized_aim = HumanizedAim()  # Reset humanized aim
        self.consecutive_aims = 0  # Reset consecutive aims
        return self.is_active
    
    def initialize(self):
        """Initialize aimbot with necessary addresses"""
        # Set view angles address
        self.view_angles_address = self.memory.engine_module + Offsets.dwViewAngles
        print(f"View angles address: {hex(self.view_angles_address)}")
        
        # Initialize offsets dynamically
        Offsets.initialize(self.memory)
        print(f"Offsets initialized")
        print(f"Local player offset: {hex(Offsets.dwLocalPlayer)}")
        print(f"Entity list offset: {hex(Offsets.dwEntityList)}")
        print(f"View angles offset: {hex(Offsets.dwViewAngles)}")
        
    def get_best_target(self, local_player, players):
        """Find the best target based on FOV and distance with improved detection"""
        current_time = time.time()
        
        # DEBUG: Always reset forced break time to ensure targeting works
        self.forced_break_time = 0
        
        # Reduced target check interval (50-100ms) for more responsive targeting
        target_check_interval = random.uniform(0.05, 0.1)
        
        # Only search for new target if we don't have one or after random interval
        if self.target_lock and current_time - self.last_target_check < target_check_interval:
            # Check if locked target is still valid
            for player in players:
                if player.base_address == self.target_lock.base_address:
                    if player.is_valid() and player.is_enemy(local_player.team):
                        player.update()  # Update position
                        self.target_lock = player
                        return player
            # Target no longer valid
            self.target_lock = None
        
        # DEBUG: Always reset target switch delay to ensure targeting works
        self.target_switch_delay = 0
        
        # Find new target
        self.last_target_check = current_time
        
        # Update offsets more frequently (5% chance per target check)
        if random.random() < 0.05:
            Offsets.update_offsets()
        
        # Get current view angles
        current_angles = Vector3(
            self.memory.read_float(self.view_angles_address),
            self.memory.read_float(self.view_angles_address + 4),
            0
        )
        
        # Randomize target selection approach (sometimes prioritize distance, sometimes FOV)
        prioritize_distance = random.random() < 0.3  # 30% chance to prioritize distance
        
        # Prepare target candidates
        valid_targets = []
        
        for player in players:
            if not player.is_valid() or not player.is_enemy(local_player.team):
                continue
                
            # Get target position based on config with slight randomization
            if self.config.target_bone == "head":
                # Occasionally aim slightly off-center for more human-like behavior
                offset_x = random.uniform(-0.5, 0.5)
                offset_y = random.uniform(-0.5, 0.5)
                offset_z = random.uniform(-0.5, 0.5)
                
                target_pos = Vector3(
                    player.head_position.x + offset_x,
                    player.head_position.y + offset_y,
                    player.head_position.z + offset_z
                )
            else:
                # Body targeting with slight randomization
                offset_x = random.uniform(-1.0, 1.0)
                offset_y = random.uniform(-1.0, 1.0)
                offset_z = random.uniform(-1.0, 1.0)
                
                target_pos = Vector3(
                    player.position.x + offset_x,
                    player.position.y + offset_y,
                    player.position.z + offset_z
                )
                
            # Calculate angle to this player
            aim_angle = calculate_angle(local_player.eye_position, target_pos)
            
            # Calculate FOV (angular distance from current view)
            fov = calc_fov(current_angles, aim_angle)
            
            # Calculate distance
            distance = local_player.eye_position.distance(target_pos)
            
            # Apply a dynamic FOV limit based on distance
            # Further targets get a smaller FOV limit to prevent snapping to far targets
            dynamic_fov_limit = self.config.fov_limit * (1.0 - min(0.5, distance / 2000.0))
            
            # Check if within configured FOV limit
            if fov < dynamic_fov_limit:
                # Check visibility if enabled
                if self.config.check_visibility:
                    if not self.is_visible(local_player.eye_position, target_pos):
                        continue
                
                # Add to valid targets
                valid_targets.append((player, fov, distance))
        
        # No valid targets
        if not valid_targets:
            return None
            
        # Sort targets based on priority
        if prioritize_distance:
            valid_targets.sort(key=lambda x: x[2])  # Sort by distance
        else:
            valid_targets.sort(key=lambda x: x[1])  # Sort by FOV
            
        # Sometimes pick the second-best target for more human-like behavior (10% chance)
        target_index = 0
        if len(valid_targets) > 1 and random.random() < 0.1:
            target_index = 1
            
        best_target = valid_targets[target_index][0]
        
        # Check if this is a new target
        if self.target_lock and best_target.base_address != self.target_lock.base_address:
            # Set a small delay before switching targets (50-200ms)
            self.target_switch_delay = current_time + random.uniform(0.05, 0.2)
            return None
            
        # Check if we've been aiming at the same target too long
        if self.target_lock and best_target.base_address == self.target_lock.base_address:
            self.consecutive_aims += 1
            
            # If we've aimed too many times consecutively, take a break
            if self.consecutive_aims >= self.max_consecutive_aims:
                # Force a break of 0.5-1.5 seconds
                self.forced_break_time = current_time + random.uniform(0.5, 1.5)
                self.consecutive_aims = 0
                self.target_lock = None
                return None
        else:
            # Reset consecutive aims for new target
            self.consecutive_aims = 0
            
        self.target_lock = best_target
        
        # Print debug message when a target is found
        print(f"Target found: Distance {distance:.1f}, FOV {fov:.1f}°")
        
        return best_target
    
    def is_visible(self, from_pos, to_pos):
        """Check if target is visible with randomized results for anti-detection"""
        # This is a simplified implementation
        # A real implementation would use ray tracing through the game's BSP tree
        # or use game-specific functions to check visibility
        
        # For anti-detection, occasionally return false even if target might be visible
        # This simulates human error and makes the aimbot less predictable
        if random.random() < 0.05:  # 5% chance to "miss" a visible target
            return False
            
        # For now, we'll assume the target is visible if we found them
        # A more accurate implementation would require game-specific memory reading
        return True
        
    def aim_at_target(self, target, local_player):
        """Aim at the specified target with humanized movement"""
        if not target:
            return False
            
        current_time = time.time()
        
        # Check if we need to wait for cooldown
        if current_time - self.last_aim_time < self.aim_cooldown:
            return False
            
        # Get target position based on config with slight randomization
        if self.config.target_bone == "head":
            # Occasionally aim slightly off-center for more human-like behavior
            offset_x = random.uniform(-0.5, 0.5)
            offset_y = random.uniform(-0.5, 0.5)
            offset_z = random.uniform(-0.5, 0.5)
            
            target_pos = Vector3(
                target.head_position.x + offset_x,
                target.head_position.y + offset_y,
                target.head_position.z + offset_z
            )
        else:
            # Body targeting with slight randomization
            offset_x = random.uniform(-1.0, 1.0)
            offset_y = random.uniform(-1.0, 1.0)
            offset_z = random.uniform(-1.0, 1.0)
            
            target_pos = Vector3(
                target.position.x + offset_x,
                target.position.y + offset_y,
                target.position.z + offset_z
            )
            
        # Calculate angle to target
        aim_angle = calculate_angle(local_player.eye_position, target_pos)
        
        # Apply recoil control if enabled with randomization
        if self.config.recoil_control:
            try:
                # Use dynamic offsets for recoil
                punch_x = self.memory.read_float(local_player.base_address + 0x3020)
                punch_y = self.memory.read_float(local_player.base_address + 0x3024)
                
                # Randomize recoil control effectiveness (70-100%)
                recoil_effectiveness = random.uniform(0.7, 1.0)
                
                # Adjust aim angle for recoil
                aim_angle.x -= punch_x * self.config.recoil_scale * recoil_effectiveness
                aim_angle.y -= punch_y * self.config.recoil_scale * recoil_effectiveness
            except Exception:
                # Silently fail if recoil control fails
                pass
        
        # Normalize angles to valid ranges
        aim_angle = normalize_angles(aim_angle)
        
        # Get current view angles
        current_angles = Vector3(
            self.memory.read_float(self.view_angles_address),
            self.memory.read_float(self.view_angles_address + 4),
            0
        )
        
        # Apply reduced smoothing for more noticeable aim movement
        base_smoothing = self.config.smoothing
        
        # Calculate distance and FOV
        distance = local_player.eye_position.distance(target_pos)
        fov = calc_fov(current_angles, aim_angle)
        
        # Reduce distance factor to make aiming more aggressive at all distances
        distance_factor = min(1.0, max(0.3, distance / 1000.0))
        
        # Reduce FOV factor to make larger angle movements more aggressive
        fov_factor = min(1.0, max(0.3, fov / 10.0))
        
        # Reduce random factor variation
        random_factor = random.uniform(0.9, 1.0)
        
        # Calculate final smoothing with a lower multiplier
        smoothing = base_smoothing * distance_factor * fov_factor * random_factor * 0.7
        
        # Check if we need to prepare a new aim movement
        if self.humanized_aim.is_movement_complete():
            self.humanized_aim.prepare_aim_movement(current_angles, aim_angle, smoothing)
            
        # Get the next movement in the sequence
        movement = self.humanized_aim.get_next_movement()
        if not movement:
            return False
            
        # Extract the movement
        move_y, move_x = movement  # Swapped for mouse movement
        
        # Apply the movement
        if self.config.use_mouse_movement:
            # Convert to mouse movement with increased sensitivity for more noticeable movement
            sensitivity_variation = random.uniform(0.95, 1.05)  # 5% variation
            
            # Increase sensitivity by 50% to make movement more noticeable
            enhanced_sensitivity = self.config.mouse_sensitivity * 1.5
            
            mouse_x = int(move_y * enhanced_sensitivity * sensitivity_variation)
            mouse_y = int(move_x * enhanced_sensitivity * sensitivity_variation)
            
            # Add small random jitter
            if random.random() < 0.2:  # 20% chance to add jitter
                mouse_x += random.randint(-1, 1)
                mouse_y += random.randint(-1, 1)
                
            # Move mouse
            mouse.move(mouse_x, mouse_y, absolute=False)
            
            # Print debug message when aim is corrected
            print(f"Aim corrected: Mouse moved by {mouse_x},{mouse_y} pixels")
        else:
            # Calculate new angles
            new_x = current_angles.x + move_x
            new_y = current_angles.y + move_y
            
            # Add small random jitter
            if random.random() < 0.2:  # 20% chance to add jitter
                new_x += random.uniform(-0.05, 0.05)
                new_y += random.uniform(-0.05, 0.05)
                
            # Normalize angles
            new_angles = normalize_angles(Vector3(new_x, new_y, 0))
            
            # Write to memory with randomized timing
            if random.random() < 0.5:  # 50% chance to write x first
                self.memory.write_float(self.view_angles_address, new_angles.x)
                print(f"Aim corrected: Memory write - Pitch: {new_angles.x:.2f}")
                
                # Small delay between writes (0-2ms)
                if random.random() < 0.3:  # 30% chance for delay
                    time.sleep(random.uniform(0, 0.002))
                    
                self.memory.write_float(self.view_angles_address + 4, new_angles.y)
                print(f"Aim corrected: Memory write - Yaw: {new_angles.y:.2f}")
            else:  # Write y first
                self.memory.write_float(self.view_angles_address + 4, new_angles.y)
                print(f"Aim corrected: Memory write - Yaw: {new_angles.y:.2f}")
                
                # Small delay between writes (0-2ms)
                if random.random() < 0.3:  # 30% chance for delay
                    time.sleep(random.uniform(0, 0.002))
                    
                self.memory.write_float(self.view_angles_address, new_angles.x)
                print(f"Aim corrected: Memory write - Pitch: {new_angles.x:.2f}")
        
        # Update last aim time
        self.last_aim_time = current_time
        
        # Randomize next aim cooldown (10-50ms)
        self.aim_cooldown = random.uniform(0.01, 0.05)
        
        return True
