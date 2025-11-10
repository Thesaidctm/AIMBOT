# vector.py - Vector calculations for aimbot
import math

class Vector3:
    def __init__(self, x=0.0, y=0.0, z=0.0):
        self.x = float(x)
        self.y = float(y)
        self.z = float(z)
    
    def __sub__(self, other):
        return Vector3(self.x - other.x, self.y - other.y, self.z - other.z)
    
    def __add__(self, other):
        return Vector3(self.x + other.x, self.y + other.y, self.z + other.z)
    
    def __str__(self):
        return f"Vector3({self.x:.2f}, {self.y:.2f}, {self.z:.2f})"
    
    def length(self):
        return math.sqrt(self.x * self.x + self.y * self.y + self.z * self.z)
    
    def distance(self, other):
        return (self - other).length()
    
    def normalize(self):
        length = self.length()
        if length != 0:
            return Vector3(self.x / length, self.y / length, self.z / length)
        return Vector3()

def calculate_angle(source_pos, dest_pos):
    """Calculate angle between two 3D points"""
    delta = dest_pos - source_pos
    
    # Calculate horizontal and vertical distances
    hyp = math.sqrt(delta.x * delta.x + delta.y * delta.y)
    
    # Calculate angles in degrees
    pitch = -math.atan2(delta.z, hyp) * 180 / math.pi
    yaw = math.atan2(delta.y, delta.x) * 180 / math.pi
    
    return Vector3(pitch, yaw, 0)

def normalize_angles(angles):
    """Normalize angles to be within acceptable ranges"""
    result = Vector3(angles.x, angles.y, angles.z)
    
    # Normalize pitch (-89 to 89)
    if result.x > 89:
        result.x = 89
    elif result.x < -89:
        result.x = -89
        
    # Normalize yaw (-180 to 180)
    while result.y > 180:
        result.y -= 360
    while result.y < -180:
        result.y += 360
        
    result.z = 0
    return result

def angle_to_vector(angle):
    """Convert angle to direction vector"""
    pitch = angle.x * math.pi / 180
    yaw = angle.y * math.pi / 180
    
    sp = math.sin(pitch)
    cp = math.cos(pitch)
    sy = math.sin(yaw)
    cy = math.cos(yaw)
    
    return Vector3(cp * cy, cp * sy, -sp)

def calc_fov(view_angle, aim_angle):
    """Calculate FOV between two angles"""
    view_vector = angle_to_vector(view_angle)
    aim_vector = angle_to_vector(aim_angle)
    
    # Calculate dot product
    dot = view_vector.x * aim_vector.x + view_vector.y * aim_vector.y + view_vector.z * aim_vector.z
    
    # Convert to degrees
    return math.acos(max(min(dot, 1.0), -1.0)) * 180 / math.pi
