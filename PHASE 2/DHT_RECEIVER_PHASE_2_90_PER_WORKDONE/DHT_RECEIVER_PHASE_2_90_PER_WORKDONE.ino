#include <Arduino.h>
#include <mbedtls/gcm.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// =====================================================
// VAJRA - ESP32 #2: RECEIVER + INTRUSION DETECTION SYSTEM
// Dashboard commands over USB Serial:
// H = Manual cutoff
// R = Resume
// =====================================================

HardwareSerial Link(2);
HardwareSerial Control(1);

#define ALERT_LED_PIN 22
#define RESUME_BUTTON_PIN 19

const uint8_t AES_KEY[16] = {
  0x21, 0x43, 0x65, 0x87,
  0x10, 0x32, 0x54, 0x76,
  0x98, 0xBA, 0xDC, 0xFE,
  0x11, 0x22, 0x33, 0x44
};

const char *SHUTDOWN_COMMAND = "HALT|VAJRA2026";
const char *RESUME_COMMAND = "RESUME|VAJRA2026";

const uint32_t IDS_CUTOFF_THRESHOLD = 2;
const unsigned long TIMEOUT_MS = 5000;
const unsigned long RATE_WINDOW_MS = 1000;
const unsigned int MAX_PACKETS_PER_SECOND = 5;
const unsigned long DEBOUNCE_MS = 50;

uint64_t lastSentCounter = 0;
uint64_t lastMitmCounter = 0;

uint32_t idsAlertCount = 0;

unsigned long lastValidPacket = 0;
unsigned long rateWindowStart = 0;
unsigned long lastButtonChange = 0;

unsigned int packetsInWindow = 0;

bool receivedAnyPacket = false;
bool shutdownSent = false;
bool timeoutAlertCounted = false;

bool previousRawButtonState = HIGH;
bool stableButtonState = HIGH;

String inputBuffer;

// =====================================================
// HEX UTILITIES
// =====================================================

int hexValue(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}

bool fromHex(const String &s, uint8_t *out,
             size_t maxLen, size_t &outLen) {
  if (s.length() % 2 != 0 || s.length() / 2 > maxLen)
    return false;

  outLen = s.length() / 2;

  for (size_t i = 0; i < outLen; i++) {
    int hi = hexValue(s[2 * i]);
    int lo = hexValue(s[2 * i + 1]);

    if (hi < 0 || lo < 0)
      return false;

    out[i] = (hi << 4) | lo;
  }

  return true;
}

// =====================================================
// NONCE GENERATION
// =====================================================

void makeNonce(const char *prefix, uint64_t count,
               uint8_t nonce[12]) {
  memcpy(nonce, prefix, 4);

  for (int i = 0; i < 8; i++) {
    nonce[4 + i] = (count >> (56 - 8 * i)) & 0xFF;
  }
}

// =====================================================
// AES-GCM AUTHENTICATION
// =====================================================

bool decryptGCM(const uint8_t *cipher, size_t len,
                const uint8_t nonce[12],
                const uint8_t tag[16],
                uint8_t *plain) {
  mbedtls_gcm_context ctx;
  mbedtls_gcm_init(&ctx);

  int rc = mbedtls_gcm_setkey(
    &ctx, MBEDTLS_CIPHER_ID_AES, AES_KEY, 128
  );

  if (rc == 0) {
    rc = mbedtls_gcm_auth_decrypt(
      &ctx,
      len,
      nonce,
      12,
      nullptr,
      0,
      tag,
      16,
      cipher,
      plain
    );
  }

  mbedtls_gcm_free(&ctx);

  return rc == 0;
}

// =====================================================
// PACKET PARSING
// =====================================================

int splitFields(const String &s, String fields[],
                int maxFields) {
  int count = 0;
  int start = 0;

  for (int i = 0; i <= (int)s.length(); i++) {
    if (i == (int)s.length() || s[i] == '|') {
      if (count >= maxFields)
        return -1;

      fields[count++] = s.substring(start, i);
      start = i + 1;
    }
  }

  return count;
}

// =====================================================
// SHUTDOWN / CUTOFF
// =====================================================

void triggerShutdown(const char *reason) {
  if (shutdownSent)
    return;

  shutdownSent = true;

  digitalWrite(ALERT_LED_PIN, LOW);

  Serial.println();
  Serial.println("========== IDS CUTOFF ==========");

  Serial.print("Trigger: ");
  Serial.println(reason);

  Serial.print("Total IDS alerts: ");
  Serial.println(idsAlertCount);

  Serial.println("[LED] External LED D22 OFF");
  Serial.println("[CONTROL] Sending HALT to ESP32 .1");

  Control.println(SHUTDOWN_COMMAND);
  Control.flush();

  Serial.println("[CONTROL] HALT command sent");
  Serial.println("================================");
}

void scheduleShutdown(const char *reason) {
  if (shutdownSent)
    return;

  idsAlertCount++;

  Serial.println();
  Serial.println("========== IDS ALERT ==========");

  Serial.print("Alert number: ");
  Serial.println(idsAlertCount);

  Serial.print("Detection: ");
  Serial.println(reason);

  if (idsAlertCount >= IDS_CUTOFF_THRESHOLD) {
    triggerShutdown(reason);
  } else {
    Serial.println("[IDS] First alert recorded");
  }

  Serial.println("================================");
}

// =====================================================
// DASHBOARD COMMAND HANDLER
// H = CUTOFF
// R = RESUME
// =====================================================

void checkDashboardCommand() {
  while (Serial.available() > 0) {
    char c = (char)Serial.read();

    if (c == 'H' && !shutdownSent) {
      Serial.println("[DASHBOARD] Manual cutoff requested");

      // Set the threshold before triggering shutdown.
      idsAlertCount = IDS_CUTOFF_THRESHOLD;

      triggerShutdown("Dashboard manual cutoff");
    }
    else if (c == 'R' && shutdownSent) {
      Serial.println("[DASHBOARD] Resume requested");

      // Ask sender ESP32 #1 to resume.
      Control.println(RESUME_COMMAND);
      Control.flush();

      shutdownSent = false;
      idsAlertCount = 0;

      timeoutAlertCounted = false;
      receivedAnyPacket = false;

      // Preserve replay counters.
      digitalWrite(ALERT_LED_PIN, HIGH);

      lastValidPacket = millis();
      rateWindowStart = millis();
      packetsInWindow = 0;

      Serial.println("[MANUAL RESET] Dashboard resume");
      Serial.println("[RESUME] IDS monitoring restarted");
      Serial.println("[LED] External LED D22 ON");
    }
  }
}

// =====================================================
// PACKET RATE MONITORING
// =====================================================

void countPacket() {
  unsigned long now = millis();

  if (now - rateWindowStart >= RATE_WINDOW_MS) {
    rateWindowStart = now;
    packetsInWindow = 0;
  }

  packetsInWindow++;

  if (packetsInWindow > MAX_PACKETS_PER_SECOND) {
    scheduleShutdown("Packet flooding");
  }
}

// =====================================================
// SENSOR ANOMALY DETECTION
// =====================================================

bool sensorAnomaly(float temperature, float humidity) {
  return temperature < 10.0 ||
         temperature > 50.0 ||
         humidity < 10.0 ||
         humidity > 95.0;
}

// =====================================================
// PACKET PROCESSING AND IDS
// =====================================================

void processPacket(String packet) {
  packet.trim();

  if (packet.length() == 0 || shutdownSent)
    return;

  Serial.println();
  Serial.println("[PACKET RECEIVED]");
  Serial.println(packet);

  countPacket();

  if (shutdownSent)
    return;

  String f[5];

  if (splitFields(packet, f, 5) != 5) {
    scheduleShutdown("Invalid packet format");
    return;
  }

  bool isSender = (f[0] == "SENT");
  bool isMitm = (f[0] == "MITM");

  if (!isSender && !isMitm) {
    scheduleShutdown("Unknown packet source");
    return;
  }

  if (f[1].length() == 0) {
    scheduleShutdown("Missing counter");
    return;
  }

  for (unsigned int i = 0; i < f[1].length(); i++) {
    if (!isDigit(f[1][i])) {
      scheduleShutdown("Invalid packet counter");
      return;
    }
  }

  uint64_t count = strtoull(f[1].c_str(), nullptr, 10);

  uint64_t &lastCount =
    isSender ? lastSentCounter : lastMitmCounter;

  if (count == 0 || count <= lastCount) {
    scheduleShutdown("Replay attack");
    return;
  }

  uint8_t nonce[12];
  uint8_t cipher[128];
  uint8_t tag[16];
  uint8_t plain[129];

  size_t nonceLen = 0;
  size_t cipherLen = 0;
  size_t tagLen = 0;

  if (!fromHex(f[2], nonce, sizeof(nonce), nonceLen) ||
      nonceLen != 12 ||
      !fromHex(f[3], cipher, sizeof(cipher), cipherLen) ||
      cipherLen == 0 ||
      !fromHex(f[4], tag, sizeof(tag), tagLen) ||
      tagLen != 16) {
    scheduleShutdown("Malformed encrypted packet");
    return;
  }

  uint8_t expectedNonce[12];

  makeNonce(
    isSender ? "SENT" : "MITM",
    count,
    expectedNonce
  );

  if (memcmp(nonce, expectedNonce, 12) != 0) {
    scheduleShutdown("Nonce mismatch");
    return;
  }

  if (!decryptGCM(
        cipher,
        cipherLen,
        nonce,
        tag,
        plain)) {
    scheduleShutdown("AES-GCM authentication failure");
    return;
  }

  plain[cipherLen] = '\0';

  String payload = String((char *)plain);

  float temperature;
  float humidity;

  if (sscanf(
        payload.c_str(),
        "TEMP=%f,HUM=%f",
        &temperature,
        &humidity
      ) != 2) {
    scheduleShutdown("Invalid sensor payload");
    return;
  }

  lastCount = count;
  lastValidPacket = millis();

  receivedAnyPacket = true;
  timeoutAlertCounted = false;

  Serial.println("[AUTH OK] AES-GCM authentication successful");

  Serial.print("Temperature: ");
  Serial.print(temperature, 1);
  Serial.println(" C");

  Serial.print("Humidity: ");
  Serial.print(humidity, 1);
  Serial.println(" %");

  if (sensorAnomaly(temperature, humidity)) {
    scheduleShutdown("Sensor value anomaly");
    return;
  }

  if (isMitm) {
    scheduleShutdown("MITM demonstration packet");
    return;
  }

  Serial.println("[ACCEPTED] Normal sensor reading");
}

// =====================================================
// PHYSICAL RESUME BUTTON
// =====================================================

void checkResumeButton() {
  bool rawState = digitalRead(RESUME_BUTTON_PIN);

  if (rawState != previousRawButtonState) {
    previousRawButtonState = rawState;
    lastButtonChange = millis();
  }

  if (millis() - lastButtonChange < DEBOUNCE_MS)
    return;

  if (rawState != stableButtonState) {
    stableButtonState = rawState;

    // INPUT_PULLUP: LOW means pressed.
    if (stableButtonState == LOW && shutdownSent) {
      Serial.println("[MANUAL RESET] Button pressed");

      Control.println(RESUME_COMMAND);
      Control.flush();

      shutdownSent = false;
      idsAlertCount = 0;

      timeoutAlertCounted = false;
      receivedAnyPacket = false;

      // Preserve replay counters.
      digitalWrite(ALERT_LED_PIN, HIGH);

      lastValidPacket = millis();
      rateWindowStart = millis();
      packetsInWindow = 0;

      Serial.println("[RESUME] Command sent to ESP32 .1");
      Serial.println("[RESUME] IDS monitoring restarted");
      Serial.println("[LED] External LED D22 ON");
    }
  }
}

// =====================================================
// SETUP
// =====================================================

void setup() {
  Serial.begin(115200);

  pinMode(ALERT_LED_PIN, OUTPUT);
  digitalWrite(ALERT_LED_PIN, HIGH);

  pinMode(RESUME_BUTTON_PIN, INPUT_PULLUP);

  // Receive packets from ESP32 #3.
  Link.begin(9600, SERIAL_8N1, 16, 17);

  // Receive on GPIO27; transmit HALT/RESUME on GPIO18.
  Control.begin(9600, SERIAL_8N1, 27, 18);

  rateWindowStart = millis();

  Serial.println("ESP32 .2 - RECEIVER + IDS");
  Serial.println("UART2 RX: D16 from .3");
  Serial.println("UART1 TX: D18 to .1");
  Serial.println("Resume button: D19 to GND");
  Serial.println("External LED: D22");
  Serial.println("Dashboard commands: H=CUTOFF, R=RESUME");
}

// =====================================================
// MAIN LOOP
// =====================================================

void loop() {
  // Check dashboard USB serial commands first.
  checkDashboardCommand();

  // Check physical resume button.
  checkResumeButton();

  // Receive packets from the intruder / communication link.
  while (Link.available()) {
    char c = (char)Link.read();

    if (c == '\n') {
      processPacket(inputBuffer);
      inputBuffer = "";
    }
    else if (c != '\r') {
      if (inputBuffer.length() < 400) {
        inputBuffer += c;
      }
      else {
        inputBuffer = "";
        scheduleShutdown("Oversized packet");
      }
    }
  }

  // Sensor communication timeout detection.
  if (receivedAnyPacket &&
      !shutdownSent &&
      !timeoutAlertCounted &&
      millis() - lastValidPacket >= TIMEOUT_MS) {

    timeoutAlertCounted = true;

    scheduleShutdown("Sensor data timeout");
  }
}