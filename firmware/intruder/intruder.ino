#include <Arduino.h>
#include <mbedtls/gcm.h>

HardwareSerial Link(2);
#define LED_PIN 2

const uint8_t AES_KEY[16] = {
  0x21, 0x43, 0x65, 0x87,
  0x10, 0x32, 0x54, 0x76,
  0x98, 0xBA, 0xDC, 0xFE,
  0x11, 0x22, 0x33, 0x44
};

char mode = 'n';
uint64_t mitmCounter = 0;
String lastPacket;

void blinkTX() {
  digitalWrite(LED_PIN, HIGH);
  delay(50);
  digitalWrite(LED_PIN, LOW);
}

String toHex(const uint8_t *data, size_t len) {
  const char *digits = "0123456789ABCDEF";
  String out;
  for (size_t i = 0; i < len; i++) {
    out += digits[data[i] >> 4];
    out += digits[data[i] & 0x0F];
  }
  return out;
}

int hexValue(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}

bool fromHex(const String &s, uint8_t *out,
             size_t maxLen, size_t &outLen) {
  if (s.length() % 2 != 0 ||
      s.length() / 2 > maxLen) return false;

  outLen = s.length() / 2;
  for (size_t i = 0; i < outLen; i++) {
    int hi = hexValue(s[2 * i]);
    int lo = hexValue(s[2 * i + 1]);
    if (hi < 0 || lo < 0) return false;
    out[i] = (hi << 4) | lo;
  }
  return true;
}

void makeNonce(const char *prefix, uint64_t count,
               uint8_t nonce[12]) {
  memcpy(nonce, prefix, 4);
  for (int i = 0; i < 8; i++) {
    nonce[4 + i] = (count >> (56 - 8 * i)) & 0xFF;
  }
}

bool decryptGCM(const uint8_t *cipher, size_t len,
                const uint8_t nonce[12],
                const uint8_t tag[16], uint8_t *plain) {
  mbedtls_gcm_context ctx;
  mbedtls_gcm_init(&ctx);

  int rc = mbedtls_gcm_setkey(
    &ctx, MBEDTLS_CIPHER_ID_AES, AES_KEY, 128
  );

  if (rc == 0) {
    rc = mbedtls_gcm_auth_decrypt(
      &ctx, len, nonce, 12, nullptr, 0,
      tag, 16, cipher, plain
    );
  }

  mbedtls_gcm_free(&ctx);
  return rc == 0;
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

int splitFields(const String &s, String fields[],
                int maxFields) {
  int count = 0;
  int start = 0;

  for (int i = 0; i <= (int)s.length(); i++) {
    if (i == (int)s.length() || s[i] == '|') {
      if (count >= maxFields) return -1;
      fields[count++] = s.substring(start, i);
      start = i + 1;
    }
  }
  return count;
}

bool decryptSenderPacket(const String &packet,
                         String &plainText) {
  String f[5];
  if (splitFields(packet, f, 5) != 5 ||
      f[0] != "SENT") return false;

  uint8_t nonce[12], cipher[128], tag[16], plain[129];
  size_t nonceLen, cipherLen, tagLen;

  if (!fromHex(f[2], nonce, sizeof(nonce), nonceLen) ||
      nonceLen != 12 ||
      !fromHex(f[3], cipher, sizeof(cipher), cipherLen) ||
      !fromHex(f[4], tag, sizeof(tag), tagLen) ||
      tagLen != 16 || cipherLen == 0) return false;

  uint64_t count = strtoull(f[1].c_str(), nullptr, 10);
  uint8_t expectedNonce[12];
  makeNonce("SENT", count, expectedNonce);

  if (memcmp(nonce, expectedNonce, 12) != 0) return false;
  if (!decryptGCM(cipher, cipherLen, nonce, tag, plain))
    return false;

  plain[cipherLen] = '\0';
  plainText = String((char *)plain);
  return true;
}

void forgePacket(const char *payload) {
  size_t len = strlen(payload);
  if (len == 0 || len > 120) return;

  uint8_t nonce[12], cipher[128], tag[16];
  mitmCounter++;
  makeNonce("MITM", mitmCounter, nonce);

  if (!encryptGCM((const uint8_t *)payload, len,
                  nonce, cipher, tag)) {
    Serial.println("[ERROR] Forging failed");
    return;
  }

  String packet = "MITM|";
  packet += String((unsigned long long)mitmCounter);
  packet += "|" + toHex(nonce, 12);
  packet += "|" + toHex(cipher, len);
  packet += "|" + toHex(tag, 16);

  Link.println(packet);
  blinkTX();
  lastPacket = packet;

  Serial.println("[TX] Forged packet transmitted; LED blinked");
}

void handlePacket(String packet) {
  packet.trim();
  if (packet.length() == 0) return;

  if (mode == 'd') {
    Serial.println("[DROP] Packet suppressed");
    return;
  }

  if (mode == 'r') {
    if (lastPacket.length()) {
      Link.println(lastPacket);
      blinkTX();
      Serial.println("[REPLAY] Packet resent; LED blinked");
    } else {
      Serial.println("[REPLAY] No saved packet");
    }
    return;
  }

  if (mode == 'n') {
    Link.println(packet);
    blinkTX();
    lastPacket = packet;
    Serial.println("[NORMAL] Packet forwarded; LED blinked");
    return;
  }

  String original;
  if (!decryptSenderPacket(packet, original)) {
    Serial.println("[ERROR] Cannot authenticate/decrypt sender packet");
    return;
  }

  if (mode == 'f') {
    Serial.println("[ATTACK DEMO] Sending false sensor reading");
    forgePacket("TEMP=85.0,HUM=5.0");
  } else if (mode == 'b') {
    Serial.println("[ATTACK DEMO] Sending burst of test packets");
    for (int i = 0; i < 10; i++) {
      forgePacket("TEMP=25.0,HUM=50.0");
      delay(10);
    }
  }
}

void setup() {
  Serial.begin(115200);
  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_PIN, LOW);

  // .1 TX17 -> .3 RX16; .3 TX17 -> .2 RX16
  Link.begin(9600, SERIAL_8N1, 16, 17);

  Serial.println("ESP32 .3: Inline lab packet demonstration");
  Serial.println("Modes: n=normal, f=false readings, b=burst, d=drop, r=replay");
}

void loop() {
  if (Serial.available()) {
    char c = (char)Serial.read();
    if (c == 'n' || c == 'f' || c == 'b' ||
        c == 'd' || c == 'r') {
      mode = c;
      Serial.print("Mode set to: ");
      Serial.println(mode);
    }
  }

  static String input;

  while (Link.available()) {
    char c = (char)Link.read();

    if (c == '\n') {
      handlePacket(input);
      input = "";
    } else if (c != '\r') {
      if (input.length() < 400) input += c;
      else input = "";
    }
  }
}