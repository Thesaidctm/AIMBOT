# offsets.py - Dynamic memory offsets for Counter-Strike 1.6
import random
import time
import struct

# 🔴 fallback global (já fica disponível mesmo antes de qualquer init)
FALLBACK_OFFSETS = {
    # Client
    "dwLocalPlayer": 0x00FB8154,
    "dwEntityList": 0x00FBEEF4,

    # Player
    "m_iTeam": 0x9C,
    "m_iHealth": 0xA0,
    "m_vecOrigin": 0x88,
    "m_vecViewOffset": 0x7C,

    # Engine
    "dwViewAngles": 0x00ABCF74,
    "dwClientState": 0x00ABCF60,

    # Bones
    "m_dwBoneMatrix": 0x2698,
}

class PatternScanner:
    """Pattern scanner to find memory signatures dynamically"""

    @staticmethod
    def find_pattern(memory_manager, module_base, pattern, mask, offset=0):
        try:
            module_size = 0x2000000  # 32MB
            chunk_size = 0x10000     # 64KB
            start_offset = random.randint(0, 0x1000)

            for chunk_start in range(start_offset, module_size, chunk_size):
                if random.random() < 0.05:
                    time.sleep(random.uniform(0.001, 0.005))

                chunk_data = memory_manager.read_bytes(
                    module_base + chunk_start,
                    min(chunk_size, module_size - chunk_start)
                )
                if not chunk_data or len(chunk_data) < len(pattern):
                    continue

                for i in range(len(chunk_data) - len(pattern) + 1):
                    ok = True
                    for j in range(len(pattern)):
                        if mask[j] == "x" and pattern[j] != chunk_data[i + j]:
                            ok = False
                            break
                    if ok:
                        return module_base + chunk_start + i + offset

            return 0
        except Exception:
            return 0


class OffsetManager:
    """Manager for dynamic offset calculation"""

    def __init__(self, memory_manager):
        self.memory = memory_manager
        self.last_update = 0
        self.update_interval = random.uniform(300, 600)
        self.offsets = {}
        self.fallback_offsets = FALLBACK_OFFSETS.copy()
        # força primeira vez
        self.update_offsets(force=True)

    def _try_detect_player_struct(self, local_player_addr):
        """tenta achar health/time andando na struct"""
        if not local_player_addr:
            return

        found_team = None
        found_health = None

        for off in range(0, 0x200, 4):
            val = self.memory.read_int(local_player_addr + off)

            if found_team is None and 1 <= val <= 5:
                found_team = off

            if found_health is None and 1 <= val <= 100:
                found_health = off

            if found_team is not None and found_health is not None:
                break

        if found_team is not None:
            self.offsets["m_iTeam"] = found_team
            print(f"[auto] Detected m_iTeam at +0x{found_team:02X}")

        if found_health is not None:
            self.offsets["m_iHealth"] = found_health
            print(f"[auto] Detected m_iHealth at +0x{found_health:02X}")

    def update_offsets(self, force=False):
        try:
            now = time.time()
            if not force and (now - self.last_update < self.update_interval):
                return

            self.last_update = now
            self.update_interval = random.uniform(300, 600)

            print("Updating offsets...")

            scanner = PatternScanner()

            base_module = self.memory.client_module  # vamos padronizar

            # 1) LocalPlayer
            local_player_pattern = b"\x8B\x0D\x00\x00\x00\x00\x8B\x01\x8B\x40\x00\xFF\xD0\x85\xC0\x74\x00\x8B"
            local_player_mask = "xx????xxxx?xxxx?x"
            result = scanner.find_pattern(self.memory, base_module, local_player_pattern, local_player_mask, 2)

            local_player_addr = 0
            if result:
                addr_bytes = self.memory.read_bytes(result, 4)
                if addr_bytes and len(addr_bytes) == 4:
                    real_addr = struct.unpack("<I", addr_bytes)[0]
                    self.offsets["dwLocalPlayer"] = real_addr - base_module
                    local_player_addr = real_addr
                    print("Found LocalPlayer offset:", hex(self.offsets["dwLocalPlayer"]))
            else:
                print("LocalPlayer pattern not found, using fallback")
                fallback_ptr = self.memory.read_int(self.memory.client_module + self.fallback_offsets["dwLocalPlayer"])
                if fallback_ptr:
                    local_player_addr = fallback_ptr

            # 2) EntityList
            entity_list_pattern = b"\x05\x00\x00\x00\x00\xC1\xE1\x04\x05\x00\x00\x00\x00"
            entity_list_mask = "x????xxxx????"
            result = scanner.find_pattern(self.memory, self.memory.client_module, entity_list_pattern, entity_list_mask, 9)

            if result:
                addr_bytes = self.memory.read_bytes(result, 4)
                if addr_bytes and len(addr_bytes) == 4:
                    self.offsets["dwEntityList"] = struct.unpack("<I", addr_bytes)[0] - self.memory.client_module
                    print("Found EntityList offset:", hex(self.offsets["dwEntityList"]))

            # 3) ViewAngles
            view_angles_pattern = b"\xD9\x00\x00\x00\x00\x00\xD8\x0D\x00\x00\x00\x00\xDF\xE0\xF6\xC4\x00\x7A"
            view_angles_mask = "x?????xx????xxx?x"
            result = scanner.find_pattern(self.memory, self.memory.engine_module, view_angles_pattern, view_angles_mask, 1)

            if result:
                addr_bytes = self.memory.read_bytes(result, 4)
                if addr_bytes and len(addr_bytes) == 4:
                    self.offsets["dwViewAngles"] = struct.unpack("<I", addr_bytes)[0] - self.memory.engine_module
                    print("Found ViewAngles offset:", hex(self.offsets["dwViewAngles"]))
            else:
                print("ViewAngles pattern not found, using fallback")

            # 4) tentar deduzir struct do player
            if local_player_addr:
                self._try_detect_player_struct(local_player_addr)

            # garante tudo
            for key, value in self.fallback_offsets.items():
                if key not in self.offsets:
                    self.offsets[key] = value
                    print("Using fallback for", key, ":", hex(value))

        except Exception as e:
            print("Error updating offsets:", str(e))
            print("Using fallback offsets")
            self.offsets = self.fallback_offsets.copy()


class Offsets:
    """
    Dynamic offsets for Counter-Strike 1.6
    (já nasce com tudo pra não dar AttributeError)
    """

    # client
    dwLocalPlayer = FALLBACK_OFFSETS["dwLocalPlayer"]
    dwEntityList = FALLBACK_OFFSETS["dwEntityList"]

    # player
    m_iTeam = FALLBACK_OFFSETS["m_iTeam"]
    m_iHealth = FALLBACK_OFFSETS["m_iHealth"]
    m_vecOrigin = FALLBACK_OFFSETS["m_vecOrigin"]
    m_vecViewOffset = FALLBACK_OFFSETS["m_vecViewOffset"]

    # engine
    dwViewAngles = FALLBACK_OFFSETS["dwViewAngles"]
    dwClientState = FALLBACK_OFFSETS["dwClientState"]

    # bones
    m_dwBoneMatrix = FALLBACK_OFFSETS["m_dwBoneMatrix"]

    BONE_HEAD = 10
    MAX_PLAYERS = 32

    @classmethod
    def initialize(cls, memory_manager):
        cls.offset_manager = OffsetManager(memory_manager)
        cls.update_offsets()

    @classmethod
    def update_offsets(cls):
        try:
            if hasattr(cls, "offset_manager"):
                cls.offset_manager.update_offsets()
                # aplica tudo sem perguntar
                for key, value in cls.offset_manager.offsets.items():
                    setattr(cls, key, value)
                print("Offsets updated successfully.")
        except Exception:
            # em caso de erro, pelo menos os fallbacks existem
            for key, value in FALLBACK_OFFSETS.items():
                setattr(cls, key, value)
