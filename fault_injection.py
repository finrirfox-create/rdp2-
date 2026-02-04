# fault_injection.py - Deterministic PIO Glitcher v9.2 (USB-Only)
# Features: PIO timing, binary protocol, watchdog, hardware trigger sync
# Target: STM32F205 via VCAP glitching

import machine
import rp2
import sys
import time
import struct
import uselect
from machine import Pin, ADC, PWM
from micropython import const

# ============================================================================
# HARDWARE CONFIGURATION
# ============================================================================
GLITCH_OUT_PIN = const(15)      # FET Gate / Voltage regulator control
TRIGGER_IN_PIN = const(14)      # Connected to STM32 NRST (monitoring)
SYNC_OUT_PIN = const(16)       # GPIO to host (glitch complete notification)
LED_PIN = const(25)            # Onboard LED

# ADC pins
VCAP_ADC_PIN = const(26)       # VCAP monitoring via divider
VDD_ADC_PIN = const(27)       # Optional VDD monitoring

# Protocol constants
FRAME_START = bytes([0xAA, 0x55])
PROTOCOL_VERSION = const(0x01)

# Timing: PIO runs at 48MHz = 20.83ns per cycle
PIO_FREQ = const(48_000_000)
NS_PER_CYCLE = const(20.83)

# Safety limits
MAX_GLITCH_NS = const(10000)   # 10us max delay
MAX_PULSE_NS = const(500)      # 500ns max pulse width (safety)
WATCHDOG_MS = const(8000)      # 8 second watchdog
POST_GLITCH_DELAY_MS = const(1)  # Delay before post-glitch ADC sampling

# Voltage divider (adjust for your hardware)
DIVIDER_MULT = 11.0

# ============================================================================
# PIO GLITCH ENGINE (Deterministic Timing)
# ============================================================================
@rp2.asm_pio(set_init=rp2.PIO.OUT_LOW, in_shiftdir=rp2.PIO.SHIFT_LEFT)
def glitch_pio():
    """
    State machine for deterministic glitch generation.
    Waits for external trigger (NRST edge), delays precisely, outputs pulse.
    
    FIFO IN: [delay_cycles:u16, pulse_cycles:u16]
    """
    # Wait for trigger high (arming)
    wait(1, pin, 0)
    # Wait for trigger low (falling edge - reset release)
    wait(0, pin, 0)
    
    # Get delay cycles from TX FIFO (blocking)
    pull(block)
    mov(x, osr)              # X = delay cycles
    
    # Precise delay loop (X cycles)
    label("delay_loop")
    jmp(x_dec, "delay_loop")
    
    # Get pulse width cycles from TX FIFO
    pull(block)
    mov(y, osr)              # Y = pulse cycles
    
    # Assert glitch output
    set(pins, 1)
    
    # Pulse width loop (Y cycles)
    label("pulse_loop")
    jmp(y_dec, "pulse_loop")
    
    # Deassert glitch output
    set(pins, 0)
    
    # Signal completion via IRQ (raised to CPU)
    irq(0)
    
    # Push completion flag to RX FIFO for CPU
    mov(isr, x)              # Move something to ISR (x is 0 here)
    push(block)              # Push to RX FIFO

# ============================================================================
# CRC8 IMPLEMENTATION (CCITT)
# ============================================================================
def crc8(data: bytes) -> int:
    """Calculate CRC-8-CCITT for binary protocol integrity."""
    crc = 0x00
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x80:
                crc = ((crc << 1) ^ 0x07) & 0xFF
            else:
                crc = (crc << 1) & 0xFF
    return crc

# ============================================================================
# USB CDC TRANSPORT
# ============================================================================
class UsbCdcTransport:
    """USB CDC (Serial over USB) transport for direct PC connection."""
    def __init__(self):
        self._poller = uselect.poll()
        self._poller.register(sys.stdin, uselect.POLLIN)

    def any(self) -> int:
        return 1 if self._poller.poll(0) else 0

    def read(self) -> bytes:
        return sys.stdin.buffer.read(64)

    def write(self, data: bytes):
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()

# ============================================================================
# HARDWARE ABSTRACTION
# ============================================================================
class GlitchHardware:
    def __init__(self):
        # Initialize watchdog (RP2040 specific)
        try:
            self.wdt = machine.WDT(timeout=WATCHDOG_MS)
        except:
            self.wdt = None  # Fallback if WDT not available
            
        # Initialize PIO state machine
        self.sm = rp2.StateMachine(
            0, 
            glitch_pio, 
            freq=PIO_FREQ,
            set_base=Pin(GLITCH_OUT_PIN, Pin.OUT),
            in_base=Pin(TRIGGER_IN_PIN, Pin.IN, Pin.PULL_UP),
            jmp_pin=Pin(TRIGGER_IN_PIN)
        )
        
        # Sync output (to host)
        self.sync_pin = Pin(SYNC_OUT_PIN, Pin.OUT)
        self.sync_pin.value(0)
        
        # LED
        self.led = Pin(LED_PIN, Pin.OUT)
        
        # ADCs
        self.vcap_adc = ADC(Pin(VCAP_ADC_PIN))
        self.vdd_adc = ADC(Pin(VDD_ADC_PIN))
        
        # Stress control (PWM on dummy load or regulator)
        try:
            self.stress_pwm = PWM(Pin(17, Pin.OUT))
            self.stress_pwm.freq(1000)
            self.stress_pwm.duty_u16(0)
        except:
            self.stress_pwm = None
            
        self.stress_level = 0.0
        self.adc_ref = 3300  # mV
        self.armed = False
        
        # Start state machine
        self.sm.active(1)
        
    def feed_watchdog(self):
        """Call periodically to prevent reset."""
        if self.wdt:
            self.wdt.feed()
        
    def read_vcap(self, samples: int = 8) -> tuple:
        """
        Read VCAP with statistical filtering.
        Returns: (mean_mv, min_mv, max_mv)
        """
        readings = []
        for _ in range(samples):
            raw = self.vcap_adc.read_u16()
            mv = (raw * self.adc_ref) / 65535 * DIVIDER_MULT
            readings.append(mv)
            time.sleep_us(100)
        
        mean_mv = sum(readings) / len(readings)
        return (mean_mv, min(readings), max(readings))
    
    def set_stress(self, level: float) -> bool:
        """Set stress level 0.0-1.0 (PWM duty)."""
        if not 0.0 <= level <= 1.0:
            return False
        self.stress_level = level
        if self.stress_pwm:
            duty = int(level * 65535)
            self.stress_pwm.duty_u16(duty)
        return True
    
    def arm_glitcher(self, delay_ns: int, pulse_ns: int) -> bool:
        """
        Arm the glitcher with specific timing.
        Returns False if parameters out of safety bounds.
        """
        # Safety checks
        if not (0 <= delay_ns <= MAX_GLITCH_NS):
            return False
        if not (0 <= pulse_ns <= MAX_PULSE_NS):
            return False
            
        # Convert ns to PIO cycles (48MHz = 20.83ns/cycle)
        delay_cycles = int((delay_ns / NS_PER_CYCLE) + 0.5)
        pulse_cycles = int((pulse_ns / NS_PER_CYCLE) + 0.5)
        
        if delay_cycles < 10 or pulse_cycles < 2:
            return False
        
        # Clear any stale FIFO data
        while self.sm.rx_fifo():
            self.sm.get()
            
        # Pre-load TX FIFOs (PIO will wait for trigger)
        self.sm.put(delay_cycles)
        self.sm.put(pulse_cycles)
        self.armed = True
        return True
    
    def check_glitch_complete(self) -> bool:
        """Check if PIO raised completion IRQ or has data in FIFO."""
        # Check if data in RX FIFO (PIO pushed at end)
        if self.sm.rx_fifo() > 0:
            _ = self.sm.get()  # Clear the dummy value
            return True
        return False
    
    def fire_glitch(self) -> dict:
        """
        Fire glitch and return measurements.
        Note: This assumes external trigger (NRST) will occur.
        For software trigger mode, we'd need different PIO code.
        """
        if not self.armed:
            return {'error': 'Not armed'}
        
        # Pre-glitch measurement
        pre_vcap, _, _ = self.read_vcap(4)
        
        # Wait for completion (with timeout)
        timeout = 1000  # 1 second
        start = time.ticks_ms()
        completed = False
        
        while time.ticks_diff(time.ticks_ms(), start) < timeout:
            if self.check_glitch_complete():
                completed = True
                break
            if self.sm.irq().flags() & 0x1:  # Check IRQ flag
                completed = True
                break
            time.sleep_us(100)
        
        if not completed:
            self.sm.restart()
            self.armed = False
            return {'error': 'Timeout waiting for trigger/completion'}
        
        # Post-glitch measurement
        time.sleep_ms(POST_GLITCH_DELAY_MS)  # Let VCAP settle
        post_vcap, post_min, post_max = self.read_vcap(4)
        droop = pre_vcap - post_vcap
        
        # Signal host via GPIO
        self.sync_pin.value(1)
        time.sleep_us(10)
        self.sync_pin.value(0)
        
        self.armed = False
        
        return {
            'pre_vcap': pre_vcap,
            'post_vcap': post_vcap,
            'droop': droop,
            'completed': True
        }

# ============================================================================
# BINARY PROTOCOL HANDLER
# ============================================================================
class BinaryProtocol:
    """Robust binary framing with CRC8 over USB CDC."""
    
    CMD_STATUS = const(0x01)
    CMD_ARM = const(0x02)
    CMD_GLITCH = const(0x03)
    CMD_STRESS = const(0x04)
    CMD_RESET = const(0x05)
    CMD_FIRE = const(0x06)  # For software-triggered mode
    
    RSP_STATUS = const(0x81)
    RSP_GLITCH_DONE = const(0x82)
    RSP_ERROR = const(0x83)
    RSP_ACK = const(0x84)
    
    def __init__(self):
        self.transport = UsbCdcTransport()
        self.hw = GlitchHardware()
        self.rx_buffer = bytearray()
        
    def send_frame(self, cmd: int, payload: bytes = b''):
        """Send framed message with CRC."""
        msg = bytes([cmd]) + payload
        crc = crc8(msg)
        frame = FRAME_START + bytes([len(msg)]) + msg + bytes([crc])
        self.transport.write(frame)
        
    def process_input(self):
        """Parse incoming USB data."""
        if self.transport.any():
            data = self.transport.read()
            if data:
                self.rx_buffer.extend(data)
                self._parse_buffer()
    
    def _parse_buffer(self):
        """Parse complete frames from buffer."""
        while len(self.rx_buffer) >= 4:
            idx = self.rx_buffer.find(FRAME_START)
            if idx == -1:
                self.rx_buffer = bytearray()
                return
            
            if idx > 0:
                self.rx_buffer = self.rx_buffer[idx:]
            
            if len(self.rx_buffer) < 3:
                return
            
            length = self.rx_buffer[2]
            total_len = 2 + 1 + 1 + length + 1
            
            if len(self.rx_buffer) < total_len:
                return
            
            frame = self.rx_buffer[:total_len]
            self.rx_buffer = self.rx_buffer[total_len:]
            
            msg = frame[3:3+length]
            rx_crc = frame[3+length]
            calc_crc = crc8(msg)
            
            if rx_crc != calc_crc:
                self.send_frame(self.RSP_ERROR, b'\x01')
                continue
            
            cmd = msg[0]
            payload = msg[1:] if length > 1 else b''
            self._handle_command(cmd, payload)
    
    def _handle_command(self, cmd: int, payload: bytes):
        """Execute commands."""
        try:
            if cmd == self.CMD_STATUS:
                vcap_mean, vcap_min, vcap_max = self.hw.read_vcap()
                status = {
                    'vcap_mean': int(vcap_mean),
                    'vcap_min': int(vcap_min),
                    'vcap_max': int(vcap_max),
                    'stress': int(self.hw.stress_level * 100),
                    'armed': int(self.hw.armed)
                }
                data = struct.pack('<HHHHBB', 
                    status['vcap_mean'], 
                    status['vcap_min'],
                    status['vcap_max'],
                    0,
                    status['stress'],
                    status['armed'])
                self.send_frame(self.RSP_STATUS, data)
                
            elif cmd == self.CMD_STRESS:
                if len(payload) >= 1:
                    level = payload[0] / 100.0
                    ok = self.hw.set_stress(level)
                    self.send_frame(self.RSP_ACK if ok else self.RSP_ERROR, b'')
                    
            elif cmd == self.CMD_ARM:
                if len(payload) == 4:
                    delay_ns, pulse_ns = struct.unpack('<HH', payload)
                    ok = self.hw.arm_glitcher(delay_ns, pulse_ns)
                    self.send_frame(self.RSP_ACK if ok else self.RSP_ERROR, b'')
                else:
                    self.send_frame(self.RSP_ERROR, b'\x02')
                    
            elif cmd == self.CMD_GLITCH:
                # Wait for external trigger to complete glitch
                result = self.hw.fire_glitch()
                
                if 'error' in result:
                    self.send_frame(self.RSP_ERROR, result['error'].encode()[:20])
                else:
                    data = struct.pack('<HHhhh', 
                        0, 0,
                        int(result['pre_vcap']),
                        int(result['post_vcap']),
                        int(result['droop']))
                    self.send_frame(self.RSP_GLITCH_DONE, data)
                
            elif cmd == self.CMD_RESET:
                self.send_frame(self.RSP_ACK, b'')
                time.sleep_ms(100)
                machine.reset()
                
            else:
                self.send_frame(self.RSP_ERROR, b'\xFF')
                
        except Exception as e:
            err_code = 0xE0 | (abs(hash(str(e))) & 0x0F)
            self.send_frame(self.RSP_ERROR, bytes([err_code]))

# ============================================================================
# MAIN LOOP
# ============================================================================
def main():
    print("RP2040 Glitcher v9.2 - Binary Protocol (USB-Only)")
    print("PIO Freq: {}MHz".format(PIO_FREQ//1000000))
    
    proto = BinaryProtocol()
    led = Pin(LED_PIN, Pin.OUT)
    led_state = 0
    last_blink = time.ticks_ms()
    
    print("Ready. Waiting for commands...")
    
    while True:
        proto.hw.feed_watchdog()
        proto.process_input()
        
        # Heartbeat LED
        if time.ticks_diff(time.ticks_ms(), last_blink) > 250:
            led_state ^= 1
            led.value(led_state)
            last_blink = time.ticks_ms()
            
        time.sleep_ms(1)  # Small yield to prevent busy-wait

if __name__ == "__main__":
    main()
