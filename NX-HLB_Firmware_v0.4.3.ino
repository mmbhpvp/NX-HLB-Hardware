#include <WiFi.h>
#include <WiFiUdp.h>
#include <Preferences.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>
#include <mbedtls/base64.h>
#include <esp_random.h>

const int listen_port = 11452; 
const int pc_port = 11451;     

WiFiUDP udp;
Preferences prefs;

String SECRET_KEY = "NX_HLB_SECURE_TEST_KEY_2026";
bool isDefaultKey = true;

String pc_ip = ""; 
String wifi_ssid = "";
String wifi_pass = "";
unsigned long lastHeartbeat = 0;
unsigned long lastWifiRetry = 0;
bool udpStarted = false;

#define NONCE_CACHE 64
String recentNonces[NONCE_CACHE];
int nonceIdx = 0;

bool isReplay(String nonce) {
  for (int i = 0; i < NONCE_CACHE; i++) {
    if (recentNonces[i] == nonce) return true;
  }
  recentNonces[nonceIdx] = nonce;
  nonceIdx = (nonceIdx + 1) % NONCE_CACHE;
  return false;
}

String generateNonce() {
  uint8_t buf[8];
  esp_fill_random(buf, 8);
  String nonce = "";
  for (int i = 0; i < 8; i++) {
    if (buf[i] < 0x10) nonce += "0";
    nonce += String(buf[i], HEX);
  }
  return nonce;
}

void printHelp() { 
  Serial.println("\n================ [ NX-HLB 安全终端 ] ================");
  Serial.println(" /status  - 查看状态");
  Serial.println(" /getkey  - 查看当前密钥指纹");
  Serial.println(" /setkey <32-64位密钥> - [仅串口] 动态设置密钥");
  Serial.println(" /set lan link <ssid> <pwd> - 设置 WiFi (空格分隔)");
  Serial.println(" /reboot  - 重启");
  Serial.println("=====================================================\n");
}

void processCommand(String cmd, bool from_serial);
String generateAuthPacket(String cmd);
bool verifyAuthPacket(String packet, String &out_cmd);
void parseLengthPrefixed(String payload, bool from_serial);

void setup() {
  Serial.begin(115200);
  delay(1000);
  pinMode(48, OUTPUT);
  
  prefs.begin("wifi_config", false);
  wifi_ssid = prefs.getString("ssid", "");
  wifi_pass = prefs.getString("pass", "");
  
  String saved_key = prefs.getString("esp_key", "");
  if (saved_key != "") {
    SECRET_KEY = saved_key;
    isDefaultKey = false;
  }
  
  printHelp();
  if (isDefaultKey) {
    Serial.println("\033[93m[SEC] 警告: 正在使用默认密钥，请通过 /setkey 修改！\033[0m");
  }
  
  if (wifi_ssid != "") {
    WiFi.begin(wifi_ssid.c_str(), wifi_pass.c_str());
    int retries = 0;
    while (WiFi.status() != WL_CONNECTED && retries < 20) {
      delay(500); Serial.print("."); retries++;
    }
  }
}

// === 签名生成 (PC 端将明文转 Base64 再签名，ESP32 端需匹配) ===
String generateAuthPacket(String cmd) {
  size_t out_len;
  unsigned char b64_buf[512];
  mbedtls_base64_encode(b64_buf, sizeof(b64_buf), &out_len, (const unsigned char*)cmd.c_str(), cmd.length());
  String b64_cmd = String((char*)b64_buf);
  
  String nonce = generateNonce();
  String raw = b64_cmd + ";" + nonce;
  
  byte hmacResult[32];
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
  mbedtls_md_hmac_starts(&ctx, (const unsigned char*)SECRET_KEY.c_str(), SECRET_KEY.length());
  mbedtls_md_hmac_update(&ctx, (const unsigned char*)raw.c_str(), raw.length());
  mbedtls_md_hmac_finish(&ctx, hmacResult);
  mbedtls_md_free(&ctx);
  
  String sig = "";
  for(int i = 0; i < 32; i++) {
    if(hmacResult[i] < 0x10) sig += "0";
    sig += String(hmacResult[i], HEX);
  }
  return raw + ";" + sig;
}

// === 签名验证与 Base64 解码 ===
bool verifyAuthPacket(String packet, String &out_cmd) {
  int lastSemi = packet.lastIndexOf(';');
  if (lastSemi < 0) return false;
  int secondLastSemi = packet.lastIndexOf(';', lastSemi - 1);
  if (secondLastSemi < 0) return false;
  
  String b64_cmd = packet.substring(0, secondLastSemi);
  String nonce = packet.substring(secondLastSemi + 1, lastSemi);
  String sig = packet.substring(lastSemi + 1);
  
  if (nonce.length() == 0 || nonce.length() > 32) return false;
  
  String raw = b64_cmd + ";" + nonce;
  byte hmacResult[32];
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
  mbedtls_md_hmac_starts(&ctx, (const unsigned char*)SECRET_KEY.c_str(), SECRET_KEY.length());
  mbedtls_md_hmac_update(&ctx, (const unsigned char*)raw.c_str(), raw.length());
  mbedtls_md_hmac_finish(&ctx, hmacResult);
  mbedtls_md_free(&ctx);
  
  String expected_sig = "";
  for(int i = 0; i < 32; i++) {
    if(hmacResult[i] < 0x10) expected_sig += "0";
    expected_sig += String(hmacResult[i], HEX);
  }
  
  if (expected_sig == sig) {
    if (isReplay(nonce)) return false;
    
    // 验签通过，解码 Base64 还原真实指令
    size_t out_len;
    unsigned char cmd_buf[512];
    if (mbedtls_base64_decode(cmd_buf, sizeof(cmd_buf), &out_len, (const unsigned char*)b64_cmd.c_str(), b64_cmd.length()) == 0) {
      cmd_buf[out_len] = '\0';
      out_cmd = String((char*)cmd_buf);
      return true;
    }
  }
  return false;
}

// === 核心修复：兼容串口输入(按空格)与PC端下发(长度前缀) ===
void parseLengthPrefixed(String payload, bool from_serial) {
  String prefix = "/set lan link ";
  int pos = payload.indexOf(prefix);
  if (pos < 0) return;
  String data = payload.substring(pos + prefix.length());
  
  String ssid = "";
  String pwd = "";

  if (from_serial) {
    // === 1. 串口手动输入，直接用空格分割 ===
    int spacePos = data.indexOf(' ');
    if (spacePos > 0) {
      ssid = data.substring(0, spacePos);
      pwd = data.substring(spacePos + 1);
    } else {
      Serial.println("[ERROR] 格式错误。正确格式: /set lan link <SSID> <PWD>");
      return;
    }
  } else {
    // === 2. PC端网络下发，严格按长度前缀解析 ===
    int colon1 = data.indexOf(':');
    if (colon1 < 0) return;
    int ssidLen = data.substring(0, colon1).toInt();
    if (ssidLen <= 0 || ssidLen > 32) return; 
    
    int ssidStart = colon1 + 1;
    if (ssidStart + ssidLen > data.length()) return;
    ssid = data.substring(ssidStart, ssidStart + ssidLen);
    
    int spacePos = data.indexOf(' ', ssidStart + ssidLen);
    if (spacePos < 0) return;
    String pwdPart = data.substring(spacePos + 1);
    
    int colon2 = pwdPart.indexOf(':');
    if (colon2 < 0) return;
    int pwdLen = pwdPart.substring(0, colon2).toInt();
    if (pwdLen <= 0 || pwdLen > 64) return; 
    
    int pwdStart = colon2 + 1;
    if (pwdStart + pwdLen > pwdPart.length()) return;
    pwd = pwdPart.substring(pwdStart, pwdStart + pwdLen);
  }
  
  if (ssid.length() > 0 && pwd.length() > 0) {
    Serial.println("解析成功, SSID: " + ssid + ", PWD: " + pwd);
    prefs.putString("ssid", ssid);
    prefs.putString("pass", pwd);
    Serial.println("保存成功，重启生效！");
    delay(1000); ESP.restart();
  } else {
    Serial.println("[ERROR] SSID 或密码不能为空！");
  }
}

void processCommand(String cmd, bool from_serial) {
  cmd.trim();
  if (cmd == "") return;
  
  if (cmd.startsWith("/set lan link ")) {
    parseLengthPrefixed(cmd, from_serial);
  }
  else if (cmd == "/reboot") {
    ESP.restart();
  }
  else if (cmd == "PC_REBOOT") { 
    Serial.println("[NET] 收到电脑重启信号，清空旧 IP，准备重新握手...");
    pc_ip = "";
  }
  else if (cmd == "/status") {
    if (pc_ip != "") {
       udp.beginPacket(pc_ip.c_str(), pc_port);
       udp.print(generateAuthPacket("[DEV_MSG] IP=" + WiFi.localIP().toString() + " RSSI=" + String(WiFi.RSSI())));
       udp.endPacket();
    }
    Serial.println("状态: 运行中");
  }
  else if (cmd == "/getkey") {
    byte shaResult[32];
    mbedtls_sha256_context sha_ctx;
    mbedtls_sha256_init(&sha_ctx);
    mbedtls_sha256_starts(&sha_ctx, 0);
    mbedtls_sha256_update(&sha_ctx, (const unsigned char*)SECRET_KEY.c_str(), SECRET_KEY.length());
    mbedtls_sha256_finish(&sha_ctx, shaResult);
    mbedtls_sha256_free(&sha_ctx);
    
    String fingerprint = "";
    for (int i = 0; i < 4; i++) {
      if (shaResult[i] < 0x10) fingerprint += "0";
      fingerprint += String(shaResult[i], HEX);
    }
    Serial.print("\033[93m[DEBUG] 当前密钥指纹: \033[0m");
    Serial.println(fingerprint);
  }
  else if (cmd.startsWith("/setkey ")) {
    if (!from_serial) {
      Serial.println("\033[91m[SEC] 拒绝远程修改密钥！\033[0m");
      return;
    }
    String newKey = cmd.substring(8);
    newKey.replace(" ", "");
    newKey.replace("\t", "");
    
    if (newKey.length() < 32 || newKey.length() > 64) {
      Serial.println("\033[91m[SEC] 密钥长度必须在 32 到 64 字符之间！\033[0m");
      return;
    }
    
    SECRET_KEY = newKey;
    isDefaultKey = false;
    prefs.putString("esp_key", newKey);
    
    Serial.println("\033[92m[OK] 密钥已更新并保存！重启生效...\033[0m");
    delay(1000);
    ESP.restart();
  }
}

void loop() {
  if (Serial.available()) {
    processCommand(Serial.readStringUntil('\n'), true); 
  }

  if (WiFi.status() != WL_CONNECTED) {
    udpStarted = false;
    pc_ip = ""; 
    
    if (millis() - lastWifiRetry > 30000) {
      lastWifiRetry = millis();
      Serial.println("[WiFi] 尝试重连...");
      WiFi.disconnect();
      WiFi.begin(wifi_ssid.c_str(), wifi_pass.c_str());
    }
    delay(100);
    return; 
  }

  if (!udpStarted) {
    udp.begin(listen_port);
    udpStarted = true;
    Serial.println("\nWiFi OK: " + WiFi.localIP().toString());
  }

  if (pc_ip == "" && millis() - lastHeartbeat > 3000) {
    lastHeartbeat = millis();
    udp.beginPacket(IPAddress(255, 255, 255, 255), pc_port); 
    udp.print(generateAuthPacket("DISCOVERY"));
    udp.endPacket();
  }

  int packetSize = udp.parsePacket();
  if (packetSize) {
    char packetBuffer[2048];
    int len = udp.read(packetBuffer, 2047);
    if (len > 0) packetBuffer[len] = 0;
    
    String out_cmd = "";
    if (verifyAuthPacket(String(packetBuffer), out_cmd)) {
      if (out_cmd.startsWith("PC_IP:")) {
        pc_ip = out_cmd.substring(6);
        Serial.println("[NET] 安全握手成功！电脑 IP: " + pc_ip);
      } else {
        processCommand(out_cmd, false); 
      }
    } else {
      Serial.println("[WARN] 拦截到非法/未配对指令！");
    }
  }

  if (pc_ip != "" && millis() - lastHeartbeat > 5000) {
    lastHeartbeat = millis();
    udp.beginPacket(pc_ip.c_str(), pc_port);
    udp.print(generateAuthPacket("HEARTBEAT"));
    udp.endPacket();
  }
}