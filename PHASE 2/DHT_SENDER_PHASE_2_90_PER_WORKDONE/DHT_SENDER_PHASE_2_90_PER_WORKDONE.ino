#include <Arduino.h>
#include <DHT.h>
#include <mbedtls/gcm.h>
#include <string.h>
#include <stdio.h>

#define DHT_PIN 23
#define DHT_TYPE DHT11

#define DATA_RX_PIN 16
#define DATA_TX_PIN 17

#define CONTROL_RX_PIN 18
#define CONTROL_TX_PIN 27

HardwareSerial Link(2);
HardwareSerial Control(1);

DHT dht(DHT_PIN, DHT_TYPE);

const uint8_t AES_KEY[16] = {
  0x21, 0x43, 0x65, 0x87,
  0x10, 0x32, 0x54, 0x76,
  0x98, 0xBA, 0xDC, 0xFE,
  0x11, 0x22, 0x33, 0x44
};

uint64_t packetCounter = 0;
bool sensorHalted = false;

unsigned long lastSendTime = 0;
const unsigned long SEND_INTERVAL_MS = 2000;

String controlBuffer;

void toHex(const uint8_t *data, size_t len, String &out) {
  const char hexChars[] = "0123456789ABCDEF";
  out = "";

  for (size_t i = 0; i < len; i++) {
    out += hexChars[(data[i] >> 4) & 0x0F];
    out += hexChars[data[i] & 0x0F];
  }
}

void makeNonce(uint64_t count, uint8_t nonce[12]) {
  memcpy(nonce, "SENT", 4);

  for (int i = 0; i < 8; i++) {
    nonce[4 + i] = (count >> (56 - 8 * i)) & 0xFF;
  }
}

bool encryptGCM(const uint8_t *plain, size_t len,
                const uint8_t nonce[12],
                uint8_t *cipher, uint8_t tag[16]) {
  mbedtls_gcm_context ctx;
  mbedtls_gcm_init(&ctx);

  int rc = mbedtls_gcm_setkey(
    &ctx, MBEDTLS_CIPHER_ID_AES, AES_KEY, 128
  );

  if (rc == 0) {
    rc = mbedtls_gcm_crypt_and_tag(
      &ctx, MBEDTLS_GCM_ENCRYPT, len,
      nonce, 12, nullptr, 0,
      plain, cipher, 16, tag
    );
  }

  mbedtls_gcm_free(&ctx);
  return rc == 0;
}

void checkControl() {
  while (Control.available() > 0) {
    char c = (char)Control.read();

    if (c == '\n') {
      controlBuffer.trim();

      if (controlBuffer == "HALT|VAJRA2026") {
        sensorHalted = true;
        Serial.println("[HALT] Sensor transmission stopped");
      } else if (controlBuffer == "RESUME|VAJRA2026") {
        sensorHalted = false;
        lastSendTime = millis() - SEND_INTERVAL_MS;
        Serial.println("[RESUME] Sensor transmission restarted");
      } else if (controlBuffer.length() > 0) {
        Serial.print("[CONTROL] Unknown command: ");
        Serial.println(controlBuffer);
      }

      controlBuffer = "";
    } else if (c != '\r') {
      if (controlBuffer.length() < 80) {
        controlBuffer += c;
      } else {
        controlBuffer = "";
      }
    }
  }
}

void sendEncrypted(float temperature, float humidity) {
  if (sensorHalted) return;

  char payload[80];
  snprintf(payload, sizeof(payload),
           "TEMP=%.1f,HUM=%.1f", temperature, humidity);

  size_t plainLen = strlen(payload);

  uint8_t nonce[12];
  uint8_t cipher[128];
  uint8_t tag[16];

  packetCounter++;
  makeNonce(packetCounter, nonce);

  if (!encryptGCM((const uint8_t *)payload, plainLen,
                  nonce, cipher, tag)) {
    Serial.println("[ERROR] AES-GCM encryption failed");
    return;
  }

  String nonceHex, cipherHex, tagHex;
  toHex(nonce, sizeof(nonce), nonceHex);
  toHex(cipher, plainLen, cipherHex);
  toHex(tag, sizeof(tag), tagHex);

  String packet =
    "SENT|" + String((unsigned long long)packetCounter) +
    "|" + nonceHex + "|" + cipherHex + "|" + tagHex;

  checkControl();
  if (sensorHalted) return;

  Link.println(packet);
  Link.flush();

  Serial.println("[TRANSMISSION SENT]");
  Serial.print("Reading #: ");
  Serial.println((unsigned long long)packetCounter);
  Serial.print("Temperature: ");
  Serial.print(temperature, 1);
  Serial.println(" C");
  Serial.print("Humidity: ");
  Serial.print(humidity, 1);
  Serial.println(" %");
}

void setup() {
  Serial.begin(115200);

  Link.begin(9600, SERIAL_8N1, DATA_RX_PIN, DATA_TX_PIN);
  Control.begin(9600, SERIAL_8N1, CONTROL_RX_PIN, CONTROL_TX_PIN);

  dht.begin();

  Serial.println("ESP32 .1 - SENSOR TRANSMITTER");
  Serial.println("Data UART2 TX: D17 -> ESP32 .3");
  Serial.println("Control UART1 RX: D18 <- ESP32 .2");
  Serial.println("Built-in LED disabled");
}

void loop() {
  checkControl();

  if (sensorHalted) {
    delay(10);
    return;
  }

  if (millis() - lastSendTime >= SEND_INTERVAL_MS) {
    lastSendTime = millis();

    checkControl();
    if (sensorHalted) return;

    float temperature = dht.readTemperature();
    float humidity = dht.readHumidity();

    if (isnan(temperature) || isnan(humidity)) {
      Serial.println("[ERROR] DHT11 reading failed");
      return;
    }

    checkControl();
    if (sensorHalted) return;

    sendEncrypted(temperature, humidity);
  }

  delay(5);
}