#include <ESP8266WiFi.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>

extern "C" {
  #include "user_interface.h"
}

// =======================================================
// ESPNoted v1.0
// IdeaSpark ESP8266 + built-in SSD1306 OLED
// Passive network recon / defensive monitor firmware
// =======================================================

// Built-in OLED pins for your IdeaSpark ESP8266 OLED board
#define OLED_SDA 12   // D6 / GPIO12
#define OLED_SCL 14   // D5 / GPIO14

#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_RESET -1
#define OLED_ADDR 0x3C

// BOOT / FLASH button
#define BUTTON_PIN 0  // GPIO0, active LOW

Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);

// =======================================================
// BUTTON CONFIG
// =======================================================

const unsigned long DEBOUNCE_MS = 35;
const unsigned long DOUBLE_CLICK_MS = 330;
const unsigned long LONG_PRESS_MS = 850;

bool lastRawButton = HIGH;
bool stableButton = HIGH;
bool lastStableButton = HIGH;

unsigned long lastDebounceTime = 0;
unsigned long pressStartTime = 0;
unsigned long lastReleaseTime = 0;

bool waitingForDouble = false;
bool longPressFired = false;

enum ButtonEvent {
  BTN_NONE,
  BTN_SHORT,
  BTN_DOUBLE,
  BTN_LONG
};

// =======================================================
// SCREEN / MODE CONFIG
// =======================================================

enum ScreenMode {
  SCREEN_SPLASH,
  SCREEN_MENU,

  SCREEN_NETWORK_SCAN,
  SCREEN_ACCESS_POINTS,
  SCREEN_AP_DETAILS,
  SCREEN_SIGNAL_TRACKER,
  SCREEN_CHANNELS,
  SCREEN_OPEN_NETWORKS,
  SCREEN_HIDDEN_NETWORKS,
  SCREEN_ROGUE_AP_WATCH,

  SCREEN_PACKET_MONITOR,
  SCREEN_DEAUTH_MONITOR,
  SCREEN_PROBE_MONITOR,
  SCREEN_EVIDENCE_LOG,

  SCREEN_OLED_TEST,
  SCREEN_DEVICE_INFO,
  SCREEN_BATTERY_RAW,
  SCREEN_RESTART,
  SCREEN_ABOUT
};

ScreenMode screen = SCREEN_SPLASH;

enum SnifferMode {
  SNIFFER_OFF,
  SNIFFER_PACKET_MONITOR,
  SNIFFER_DEAUTH_MONITOR,
  SNIFFER_PROBE_MONITOR
};

SnifferMode snifferMode = SNIFFER_OFF;

// =======================================================
// MENU
// =======================================================

const char* menuItems[] = {
  "Network Scan",
  "Access Points",
  "AP Details",
  "Signal Tracker",
  "Channels",
  "Open Networks",
  "Hidden Networks",
  "Rogue AP Watch",
  "Packet Monitor",
  "Deauth Monitor",
  "Probe Monitor",
  "Evidence Log",
  "OLED Test",
  "Device Info",
  "Battery Raw",
  "Restart",
  "About"
};

const int MENU_COUNT = sizeof(menuItems) / sizeof(menuItems[0]);

int menuIndex = 0;
int menuTop = 0;

// =======================================================
// WIFI SCAN DATA
// =======================================================

int networkCount = 0;
int sortedIndex[50];
int channelCount[14];

bool hasScanned = false;
int selectedNetwork = 0;
int browserTop = 0;

String trustedSSID = "";
String trustedBSSID = "";
bool trustedSet = false;

// =======================================================
// SNIFFER DATA
// =======================================================

bool snifferRunning = false;
bool autoHop = true;

uint8_t watchChannel = 1;

unsigned long lastHopTime = 0;
unsigned long lastRateTime = 0;
unsigned long lastScreenUpdate = 0;
unsigned long lastOledAnim = 0;

const unsigned long HOP_MS = 1100;
const unsigned long RATE_MS = 1000;
const unsigned long SNIFFER_SCREEN_MS = 250;
const unsigned long OLED_ANIM_MS = 80;

volatile uint32_t totalPackets = 0;
volatile uint32_t mgmtPackets = 0;
volatile uint32_t dataPackets = 0;
volatile uint32_t ctrlPackets = 0;

volatile uint32_t beaconPackets = 0;
volatile uint32_t probeReqPackets = 0;
volatile uint32_t probeRespPackets = 0;

volatile uint32_t deauthPackets = 0;
volatile uint32_t disassocPackets = 0;

volatile int8_t lastRssi = 0;
volatile uint8_t lastChannelSeen = 0;

volatile uint8_t lastSrcMac[6] = {0};
volatile uint8_t lastDstMac[6] = {0};
volatile uint8_t lastBssidMac[6] = {0};

uint32_t lastTotalPackets = 0;
uint32_t lastAttackPackets = 0;
uint32_t lastProbePackets = 0;

int pps = 0;
int attackPps = 0;
int probePps = 0;

int attackWindow[5] = {0, 0, 0, 0, 0};
int probeWindow[5] = {0, 0, 0, 0, 0};

int winPos = 0;
int attack5s = 0;
int probe5s = 0;

// =======================================================
// ESP8266 PROMISCUOUS STRUCTS
// =======================================================

typedef struct {
  signed rssi: 8;
  unsigned rate: 4;
  unsigned is_group: 1;
  unsigned: 1;
  unsigned sig_mode: 2;
  unsigned legacy_length: 12;
  unsigned damatch0: 1;
  unsigned damatch1: 1;
  unsigned bssidmatch0: 1;
  unsigned bssidmatch1: 1;
  unsigned MCS: 7;
  unsigned CWB: 1;
  unsigned HT_length: 16;
  unsigned Smoothing: 1;
  unsigned Not_Sounding: 1;
  unsigned: 1;
  unsigned Aggregation: 1;
  unsigned STBC: 2;
  unsigned FEC_CODING: 1;
  unsigned SGI: 1;
  unsigned rxend_state: 8;
  unsigned ampdu_cnt: 8;
  unsigned channel: 4;
  unsigned: 12;
} RxControl;

typedef struct {
  RxControl rx_ctrl;
  uint8_t buf[36];
  uint16_t cnt;
  uint16_t len;
} SnifferPacketSmall;

typedef struct {
  RxControl rx_ctrl;
  uint8_t buf[112];
  uint16_t cnt;
  uint16_t len;
} SnifferPacketLarge;

// =======================================================
// HELPERS
// =======================================================

String shortText(String text, int maxLen) {
  if (text.length() <= maxLen) return text;
  if (maxLen <= 2) return text.substring(0, maxLen);
  return text.substring(0, maxLen - 2) + "..";
}

String securityName(uint8_t enc) {
  if (enc == ENC_TYPE_NONE) return "OPEN";
  if (enc == ENC_TYPE_WEP) return "WEP";
  if (enc == ENC_TYPE_TKIP) return "WPA";
  if (enc == ENC_TYPE_CCMP) return "WPA2";
  if (enc == ENC_TYPE_AUTO) return "AUTO";
  return "LOCK";
}

bool isOpenNetwork(int i) {
  return WiFi.encryptionType(i) == ENC_TYPE_NONE;
}

String shortMacFromString(String mac) {
  if (mac.length() < 17) return "------";
  return mac.substring(9, 11) + mac.substring(12, 14) + mac.substring(15, 17);
}

String shortMac(const uint8_t mac[6]) {
  char out[9];

  snprintf(
    out,
    sizeof(out),
    "%02X%02X%02X",
    mac[3],
    mac[4],
    mac[5]
  );

  return String(out);
}

String riskText() {
  if (attack5s >= 25) return "HIGH";
  if (attack5s >= 8) return "MED";
  if (attack5s >= 1) return "LOW";
  return "QUIET";
}

void uiClear() {
  display.clearDisplay();
  display.setTextColor(SSD1306_WHITE);
  display.setTextSize(1);
}

void topBar(const char* title) {
  display.setCursor(0, 0);
  display.print(title);

  display.setCursor(104, 0);
  display.print("v1");

  display.drawLine(0, 10, 127, 10, SSD1306_WHITE);
}

void bottomHint(const char* hint) {
  display.drawLine(0, 54, 127, 54, SSD1306_WHITE);
  display.setCursor(0, 56);
  display.print(hint);
}

void loading(const char* title, const char* a, const char* b) {
  uiClear();
  topBar(title);
  display.setCursor(0, 22);
  display.println(a);
  display.setCursor(0, 36);
  display.println(b);
  display.display();
}

void drawSignalBars(int x, int y, int rssi) {
  int bars = 0;

  if (rssi > -55) bars = 4;
  else if (rssi > -65) bars = 3;
  else if (rssi > -75) bars = 2;
  else if (rssi > -85) bars = 1;
  else bars = 0;

  for (int i = 0; i < 4; i++) {
    int h = (i + 1) * 3;
    int bx = x + i * 4;
    int by = y + (12 - h);

    if (i < bars) {
      display.fillRect(bx, by, 3, h, SSD1306_WHITE);
    } else {
      display.drawRect(bx, by, 3, h, SSD1306_WHITE);
    }
  }
}

// =======================================================
// BUTTON HANDLER
// =======================================================

ButtonEvent readButton() {
  ButtonEvent event = BTN_NONE;
  bool raw = digitalRead(BUTTON_PIN);

  if (raw != lastRawButton) {
    lastDebounceTime = millis();
    lastRawButton = raw;
  }

  if ((millis() - lastDebounceTime) > DEBOUNCE_MS) {
    stableButton = raw;
  }

  if (lastStableButton == HIGH && stableButton == LOW) {
    pressStartTime = millis();
    longPressFired = false;
  }

  if (stableButton == LOW && !longPressFired) {
    if (millis() - pressStartTime >= LONG_PRESS_MS) {
      longPressFired = true;
      waitingForDouble = false;
      event = BTN_LONG;
    }
  }

  if (lastStableButton == LOW && stableButton == HIGH) {
    unsigned long pressDuration = millis() - pressStartTime;

    if (!longPressFired && pressDuration < LONG_PRESS_MS) {
      if (waitingForDouble && (millis() - lastReleaseTime <= DOUBLE_CLICK_MS)) {
        waitingForDouble = false;
        event = BTN_DOUBLE;
      } else {
        waitingForDouble = true;
        lastReleaseTime = millis();
      }
    }
  }

  if (waitingForDouble && (millis() - lastReleaseTime > DOUBLE_CLICK_MS)) {
    waitingForDouble = false;
    event = BTN_SHORT;
  }

  lastStableButton = stableButton;
  return event;
}

// =======================================================
// WIFI SCAN
// =======================================================

void stopSniffer();

void sortNetworks() {
  int maxNetworks = min(networkCount, 50);

  for (int i = 0; i < maxNetworks; i++) {
    sortedIndex[i] = i;
  }

  for (int i = 0; i < maxNetworks - 1; i++) {
    for (int j = i + 1; j < maxNetworks; j++) {
      if (WiFi.RSSI(sortedIndex[j]) > WiFi.RSSI(sortedIndex[i])) {
        int temp = sortedIndex[i];
        sortedIndex[i] = sortedIndex[j];
        sortedIndex[j] = temp;
      }
    }
  }
}

void calcChannels() {
  for (int i = 0; i < 14; i++) {
    channelCount[i] = 0;
  }

  for (int i = 0; i < networkCount; i++) {
    int ch = WiFi.channel(i);

    if (ch >= 1 && ch <= 13) {
      channelCount[ch]++;
    }
  }
}

void serialDumpScan() {
  Serial.println();
  Serial.println("==== ESPNoted v1.0 Network Scan ====");
  Serial.print("Networks: ");
  Serial.println(networkCount);
  Serial.println("# | RSSI | CH | SECURITY | BSSID             | SSID");

  for (int i = 0; i < networkCount; i++) {
    int n = sortedIndex[i];

    Serial.print(i + 1);
    Serial.print(" | ");
    Serial.print(WiFi.RSSI(n));
    Serial.print(" | ");
    Serial.print(WiFi.channel(n));
    Serial.print(" | ");
    Serial.print(securityName(WiFi.encryptionType(n)));
    Serial.print(" | ");
    Serial.print(WiFi.BSSIDstr(n));
    Serial.print(" | ");

    String ssid = WiFi.SSID(n);
    if (ssid.length() == 0) ssid = "<hidden>";

    Serial.println(ssid);
  }

  Serial.println("====================================");
}

void runWiFiScan() {
  stopSniffer();

  loading("Network Scan", "Scanning networks", "Hidden included");
  delay(150);

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);

  WiFi.scanDelete();

  networkCount = WiFi.scanNetworks(false, true);

  if (networkCount < 0) networkCount = 0;
  if (networkCount > 50) networkCount = 50;

  sortNetworks();
  calcChannels();

  if (selectedNetwork >= networkCount) selectedNetwork = 0;
  browserTop = 0;

  hasScanned = true;
  serialDumpScan();
}

int countOpenAPs() {
  int count = 0;

  for (int i = 0; i < networkCount; i++) {
    if (isOpenNetwork(i)) count++;
  }

  return count;
}

int countHiddenAPs() {
  int count = 0;

  for (int i = 0; i < networkCount; i++) {
    if (WiFi.SSID(i).length() == 0) count++;
  }

  return count;
}

int getSelectedRealIndex() {
  if (!hasScanned || networkCount == 0) return -1;

  if (selectedNetwork < 0) selectedNetwork = 0;
  if (selectedNetwork >= networkCount) selectedNetwork = networkCount - 1;

  return sortedIndex[selectedNetwork];
}

void setTrustedAPFromSelection() {
  int realIndex = getSelectedRealIndex();

  if (realIndex < 0) return;

  trustedSSID = WiFi.SSID(realIndex);
  trustedBSSID = WiFi.BSSIDstr(realIndex);
  trustedSet = true;

  Serial.println();
  Serial.println("==== ESPNoted Trusted AP Set ====");
  Serial.print("SSID: ");
  Serial.println(trustedSSID);
  Serial.print("BSSID: ");
  Serial.println(trustedBSSID);
}

// =======================================================
// SNIFFER CALLBACK
// =======================================================

void ICACHE_FLASH_ATTR snifferCallback(uint8_t *buf, uint16_t len) {
  if (len < sizeof(RxControl) + 24) {
    return;
  }

  uint8_t *packet = NULL;
  RxControl *rx = NULL;

  if (len == 128) {
    SnifferPacketLarge *sniffer = (SnifferPacketLarge*) buf;
    packet = sniffer->buf;
    rx = &sniffer->rx_ctrl;
  } else {
    SnifferPacketSmall *sniffer = (SnifferPacketSmall*) buf;
    packet = sniffer->buf;
    rx = &sniffer->rx_ctrl;
  }

  if (packet == NULL || rx == NULL) return;

  uint16_t frameControl = packet[0] | (packet[1] << 8);

  uint8_t type = (frameControl & 0x0C) >> 2;
  uint8_t subtype = (frameControl & 0xF0) >> 4;

  totalPackets++;

  if (type == 0) mgmtPackets++;
  else if (type == 1) ctrlPackets++;
  else if (type == 2) dataPackets++;

  if (type == 0) {
    for (int i = 0; i < 6; i++) {
      lastDstMac[i] = packet[4 + i];
      lastSrcMac[i] = packet[10 + i];
      lastBssidMac[i] = packet[16 + i];
    }

    lastRssi = rx->rssi;
    lastChannelSeen = watchChannel;

    if (subtype == 8) {
      beaconPackets++;
    } else if (subtype == 4) {
      probeReqPackets++;
    } else if (subtype == 5) {
      probeRespPackets++;
    } else if (subtype == 12) {
      deauthPackets++;
    } else if (subtype == 10) {
      disassocPackets++;
    }
  }
}

// =======================================================
// SNIFFER CONTROL
// =======================================================

void resetStats() {
  noInterrupts();

  totalPackets = 0;
  mgmtPackets = 0;
  dataPackets = 0;
  ctrlPackets = 0;

  beaconPackets = 0;
  probeReqPackets = 0;
  probeRespPackets = 0;

  deauthPackets = 0;
  disassocPackets = 0;

  lastRssi = 0;
  lastChannelSeen = watchChannel;

  for (int i = 0; i < 6; i++) {
    lastSrcMac[i] = 0;
    lastDstMac[i] = 0;
    lastBssidMac[i] = 0;
  }

  interrupts();

  lastTotalPackets = 0;
  lastAttackPackets = 0;
  lastProbePackets = 0;

  pps = 0;
  attackPps = 0;
  probePps = 0;

  for (int i = 0; i < 5; i++) {
    attackWindow[i] = 0;
    probeWindow[i] = 0;
  }

  winPos = 0;
  attack5s = 0;
  probe5s = 0;
}

void startSniffer(SnifferMode mode) {
  stopSniffer();

  snifferMode = mode;
  resetStats();

  loading("Monitor", "Starting listener", "Passive mode");
  delay(250);

  WiFi.scanDelete();
  WiFi.disconnect();
  WiFi.mode(WIFI_STA);
  delay(100);

  wifi_promiscuous_enable(0);
  wifi_set_opmode(STATION_MODE);
  wifi_set_channel(watchChannel);
  wifi_set_promiscuous_rx_cb(snifferCallback);
  wifi_promiscuous_enable(1);

  snifferRunning = true;
  autoHop = true;

  lastHopTime = millis();
  lastRateTime = millis();
  lastScreenUpdate = millis();

  Serial.println("ESPNoted monitor started.");
}

void stopSniffer() {
  if (!snifferRunning) {
    snifferMode = SNIFFER_OFF;
    return;
  }

  wifi_promiscuous_enable(0);
  wifi_set_promiscuous_rx_cb(NULL);

  snifferRunning = false;
  snifferMode = SNIFFER_OFF;

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();

  Serial.println("ESPNoted monitor stopped.");
}

void nextChannel() {
  watchChannel++;

  if (watchChannel > 13) {
    watchChannel = 1;
  }

  if (snifferRunning) {
    wifi_set_channel(watchChannel);
  }
}

void updateRates() {
  uint32_t totalNow;
  uint32_t attackNow;
  uint32_t probeNow;

  noInterrupts();

  totalNow = totalPackets;
  attackNow = deauthPackets + disassocPackets;
  probeNow = probeReqPackets;

  interrupts();

  pps = totalNow - lastTotalPackets;
  attackPps = attackNow - lastAttackPackets;
  probePps = probeNow - lastProbePackets;

  lastTotalPackets = totalNow;
  lastAttackPackets = attackNow;
  lastProbePackets = probeNow;

  attackWindow[winPos] = attackPps;
  probeWindow[winPos] = probePps;

  winPos++;

  if (winPos >= 5) winPos = 0;

  attack5s = 0;
  probe5s = 0;

  for (int i = 0; i < 5; i++) {
    attack5s += attackWindow[i];
    probe5s += probeWindow[i];
  }
}

// =======================================================
// UI SCREENS
// =======================================================

void showSplash() {
  uiClear();

  display.setCursor(0, 0);
  display.println("ESPNoted");

  display.setCursor(0, 14);
  display.println("Network Console");

  display.setCursor(0, 28);
  display.println("ESP8266 OLED");

  display.setCursor(0, 42);
  display.println("Passive Monitor");

  display.setCursor(0, 56);
  display.println("Starting...");
  display.display();

  delay(1500);

  screen = SCREEN_MENU;
}

void showMenu() {
  uiClear();
  topBar("ESPNoted");

  if (menuIndex < menuTop) menuTop = menuIndex;
  if (menuIndex > menuTop + 3) menuTop = menuIndex - 3;

  for (int row = 0; row < 4; row++) {
    int item = menuTop + row;
    if (item >= MENU_COUNT) break;

    int y = 14 + row * 10;

    display.setCursor(0, y);

    if (item == menuIndex) display.print(">");
    else display.print(" ");

    display.print(menuItems[item]);
  }

  bottomHint("S:Down D:Enter L:Back");
  display.display();
}

void showNetworkScan() {
  uiClear();
  topBar("Network Scan");

  if (!hasScanned) {
    display.setCursor(0, 24);
    display.println("No scan yet");
    bottomHint("D:Scan L:Back");
    display.display();
    return;
  }

  int openCount = countOpenAPs();
  int hiddenCount = countHiddenAPs();

  display.setCursor(0, 14);
  display.print("APs:");
  display.print(networkCount);
  display.print(" Open:");
  display.println(openCount);

  display.setCursor(0, 24);
  display.print("Hidden:");
  display.print(hiddenCount);
  display.print(" Locked:");
  display.println(networkCount - openCount);

  if (networkCount > 0) {
    int best = sortedIndex[0];

    display.setCursor(0, 36);
    display.print("Best:");
    display.println(shortText(WiFi.SSID(best), 14));

    display.setCursor(0, 46);
    display.print(WiFi.RSSI(best));
    display.print("dBm CH");
    display.print(WiFi.channel(best));

    drawSignalBars(104, 40, WiFi.RSSI(best));
  }

  bottomHint("D:Rescan L:Back");
  display.display();
}

void showAccessPoints() {
  uiClear();
  topBar("Access Points");

  if (!hasScanned || networkCount == 0) {
    display.setCursor(0, 24);
    display.println("No APs found");
    bottomHint("D:Scan L:Back");
    display.display();
    return;
  }

  if (selectedNetwork < browserTop) browserTop = selectedNetwork;
  if (selectedNetwork > browserTop + 3) browserTop = selectedNetwork - 3;

  for (int row = 0; row < 4; row++) {
    int item = browserTop + row;
    if (item >= networkCount) break;

    int n = sortedIndex[item];
    int y = 14 + row * 10;

    String ssid = WiFi.SSID(n);
    if (ssid.length() == 0) ssid = "<hidden>";

    display.setCursor(0, y);

    if (item == selectedNetwork) display.print(">");
    else display.print(" ");

    display.print(shortText(ssid, 9));

    display.setCursor(72, y);
    display.print(WiFi.RSSI(n));

    display.setCursor(104, y);
    display.print("C");
    display.print(WiFi.channel(n));
  }

  bottomHint("S:Next D:Info L:Back");
  display.display();
}

void showAPDetails() {
  uiClear();
  topBar("AP Details");

  int realIndex = getSelectedRealIndex();

  if (realIndex < 0) {
    display.setCursor(0, 24);
    display.println("No AP selected");
    bottomHint("D:Scan L:Back");
    display.display();
    return;
  }

  String ssid = WiFi.SSID(realIndex);
  if (ssid.length() == 0) ssid = "<hidden>";

  String bssid = WiFi.BSSIDstr(realIndex);

  display.setCursor(0, 12);
  display.print("#");
  display.print(selectedNetwork + 1);
  display.print(" ");
  display.println(shortText(ssid, 16));

  display.setCursor(0, 22);
  display.print("BSSID ");
  display.println(shortMacFromString(bssid));

  display.setCursor(0, 32);
  display.print("CH:");
  display.print(WiFi.channel(realIndex));
  display.print(" RSSI:");
  display.println(WiFi.RSSI(realIndex));

  display.setCursor(0, 42);
  display.print("SEC:");
  display.print(securityName(WiFi.encryptionType(realIndex)));

  if (trustedSet && bssid == trustedBSSID) {
    display.print(" TRUST");
  }

  drawSignalBars(108, 36, WiFi.RSSI(realIndex));
  bottomHint("S:Next D:Trust L:Back");
  display.display();
}

void showSignalTracker() {
  uiClear();
  topBar("Signal Tracker");

  int realIndex = getSelectedRealIndex();

  if (realIndex < 0) {
    display.setCursor(0, 24);
    display.println("No AP selected");
    bottomHint("D:Scan L:Back");
    display.display();
    return;
  }

  String ssid = WiFi.SSID(realIndex);
  if (ssid.length() == 0) ssid = "<hidden>";

  int rssi = WiFi.RSSI(realIndex);
  int barWidth = map(constrain(rssi, -95, -35), -95, -35, 0, 118);

  display.setCursor(0, 14);
  display.println(shortText(ssid, 18));

  display.setCursor(0, 26);
  display.print("RSSI:");
  display.print(rssi);
  display.print(" dBm CH");
  display.println(WiFi.channel(realIndex));

  display.drawRect(4, 40, 120, 10, SSD1306_WHITE);
  display.fillRect(6, 42, barWidth, 6, SSD1306_WHITE);

  bottomHint("S:Next D:Rescan L:Back");
  display.display();
}

void showChannels() {
  uiClear();
  topBar("Channels");

  if (!hasScanned || networkCount == 0) {
    display.setCursor(0, 24);
    display.println("No channel data");
    bottomHint("D:Scan L:Back");
    display.display();
    return;
  }

  int maxCount = 1;

  for (int ch = 1; ch <= 13; ch++) {
    if (channelCount[ch] > maxCount) maxCount = channelCount[ch];
  }

  int bestChannel = 1;
  int bestCount = channelCount[1];

  for (int ch = 2; ch <= 13; ch++) {
    if (channelCount[ch] < bestCount) {
      bestCount = channelCount[ch];
      bestChannel = ch;
    }
  }

  display.setCursor(0, 12);
  display.print("Best CH:");
  display.print(bestChannel);
  display.print(" APs:");
  display.println(bestCount);

  for (int ch = 1; ch <= 13; ch++) {
    int x = 2 + (ch - 1) * 9;
    int barHeight = map(channelCount[ch], 0, maxCount, 0, 28);

    if (channelCount[ch] > 0) {
      display.fillRect(x, 48 - barHeight, 6, barHeight, SSD1306_WHITE);
    } else {
      display.drawRect(x, 47, 6, 1, SSD1306_WHITE);
    }

    if (ch == 1 || ch == 6 || ch == 11 || ch == 13) {
      display.setCursor(x - 1, 50);
      display.print(ch);
    }
  }

  bottomHint("D:Rescan L:Back");
  display.display();
}

void showOpenNetworks() {
  uiClear();
  topBar("Open Networks");

  if (!hasScanned || networkCount == 0) {
    display.setCursor(0, 24);
    display.println("No scan data");
    bottomHint("D:Scan L:Back");
    display.display();
    return;
  }

  int shown = 0;
  int openCount = 0;

  for (int i = 0; i < networkCount; i++) {
    int n = sortedIndex[i];

    if (isOpenNetwork(n)) {
      openCount++;

      if (shown < 4) {
        int y = 14 + shown * 10;
        String ssid = WiFi.SSID(n);
        if (ssid.length() == 0) ssid = "<hidden>";

        display.setCursor(0, y);
        display.print(openCount);
        display.print(" ");
        display.print(shortText(ssid, 10));

        display.setCursor(78, y);
        display.print(WiFi.RSSI(n));

        display.setCursor(110, y);
        display.print("C");
        display.print(WiFi.channel(n));

        shown++;
      }
    }
  }

  if (openCount == 0) {
    display.setCursor(0, 26);
    display.println("No open networks");
  }

  bottomHint("D:Rescan L:Back");
  display.display();
}

void showHiddenNetworks() {
  uiClear();
  topBar("Hidden Networks");

  if (!hasScanned || networkCount == 0) {
    display.setCursor(0, 24);
    display.println("No scan data");
    bottomHint("D:Scan L:Back");
    display.display();
    return;
  }

  int shown = 0;
  int hiddenCount = 0;

  for (int i = 0; i < networkCount; i++) {
    int n = sortedIndex[i];

    if (WiFi.SSID(n).length() == 0) {
      hiddenCount++;

      if (shown < 4) {
        int y = 14 + shown * 10;

        display.setCursor(0, y);
        display.print(hiddenCount);
        display.print(" <hidden>");

        display.setCursor(78, y);
        display.print(WiFi.RSSI(n));

        display.setCursor(110, y);
        display.print("C");
        display.print(WiFi.channel(n));

        shown++;
      }
    }
  }

  if (hiddenCount == 0) {
    display.setCursor(0, 26);
    display.println("No hidden networks");
  }

  bottomHint("D:Rescan L:Back");
  display.display();
}

void showRogueAPWatch() {
  uiClear();
  topBar("Rogue AP Watch");

  if (!trustedSet) {
    display.setCursor(0, 14);
    display.println("No trusted AP set");

    display.setCursor(0, 28);
    display.println("Open AP Details");

    display.setCursor(0, 40);
    display.println("Double = Trust AP");

    bottomHint("L:Back");
    display.display();
    return;
  }

  int rogueCount = 0;
  int strongestRogue = -1;

  for (int i = 0; i < networkCount; i++) {
    String ssid = WiFi.SSID(i);
    String bssid = WiFi.BSSIDstr(i);

    if (ssid == trustedSSID && bssid != trustedBSSID) {
      rogueCount++;

      if (strongestRogue < 0 || WiFi.RSSI(i) > WiFi.RSSI(strongestRogue)) {
        strongestRogue = i;
      }
    }
  }

  display.setCursor(0, 12);
  display.print("SSID:");
  display.println(shortText(trustedSSID, 14));

  display.setCursor(0, 22);
  display.print("Trust:");
  display.println(shortMacFromString(trustedBSSID));

  display.setCursor(0, 32);
  display.print("Clones:");
  display.println(rogueCount);

  if (rogueCount > 0 && strongestRogue >= 0) {
    display.setCursor(0, 42);
    display.print("Seen:");
    display.print(shortMacFromString(WiFi.BSSIDstr(strongestRogue)));
    display.print(" R:");
    display.println(WiFi.RSSI(strongestRogue));
  } else {
    display.setCursor(0, 42);
    display.println("Risk: OK");
  }

  bottomHint("D:Rescan L:Back");
  display.display();
}

void showPacketMonitor() {
  uint32_t t;
  uint32_t m;
  uint32_t d;
  uint32_t c;
  int8_t r;

  noInterrupts();

  t = totalPackets;
  m = mgmtPackets;
  d = dataPackets;
  c = ctrlPackets;
  r = lastRssi;

  interrupts();

  uiClear();
  topBar("Packet Monitor");

  display.setCursor(0, 12);
  display.print("CH:");
  display.print(watchChannel);
  display.print(autoHop ? " AUTO" : " LOCK");

  display.setCursor(78, 12);
  display.print("PPS:");
  display.println(pps);

  display.setCursor(0, 24);
  display.print("Total:");
  display.println(t);

  display.setCursor(0, 34);
  display.print("M:");
  display.print(m);
  display.print(" D:");
  display.print(d);
  display.print(" C:");
  display.println(c);

  display.setCursor(0, 44);
  display.print("RSSI:");
  display.print(r);
  display.print(" H:");
  display.println(ESP.getFreeHeap());

  bottomHint("S:CH D:Auto L:Back");
  display.display();
}

void showDeauthMonitor() {
  uint32_t de;
  uint32_t dis;
  int8_t r;
  uint8_t src[6];

  noInterrupts();

  de = deauthPackets;
  dis = disassocPackets;
  r = lastRssi;

  for (int i = 0; i < 6; i++) {
    src[i] = lastSrcMac[i];
  }

  interrupts();

  uiClear();
  topBar("Deauth Monitor");

  display.setCursor(0, 12);
  display.print("CH:");
  display.print(watchChannel);
  display.print(autoHop ? " AUTO" : " LOCK");

  display.setCursor(74, 12);
  display.print("R:");
  display.println(riskText());

  display.setCursor(0, 24);
  display.print("Deauth:");
  display.print(de);
  display.print(" Dis:");
  display.println(dis);

  display.setCursor(0, 34);
  display.print("1s:");
  display.print(attackPps);
  display.print(" 5s:");
  display.println(attack5s);

  display.setCursor(0, 44);
  display.print("Src:");
  display.print(shortMac(src));
  display.print(" R:");
  display.println(r);

  bottomHint("S:CH D:Auto L:Back");
  display.display();
}

void showProbeMonitor() {
  uint32_t pr;
  uint32_t resp;
  int8_t r;
  uint8_t src[6];

  noInterrupts();

  pr = probeReqPackets;
  resp = probeRespPackets;
  r = lastRssi;

  for (int i = 0; i < 6; i++) {
    src[i] = lastSrcMac[i];
  }

  interrupts();

  uiClear();
  topBar("Probe Monitor");

  display.setCursor(0, 12);
  display.print("CH:");
  display.print(watchChannel);
  display.print(autoHop ? " AUTO" : " LOCK");

  display.setCursor(0, 24);
  display.print("ProbeReq:");
  display.println(pr);

  display.setCursor(0, 34);
  display.print("Resp:");
  display.print(resp);
  display.print(" 5s:");
  display.println(probe5s);

  display.setCursor(0, 44);
  display.print("Last:");
  display.print(shortMac(src));
  display.print(" R:");
  display.println(r);

  bottomHint("S:CH D:Auto L:Back");
  display.display();
}

void showEvidenceLog() {
  uint32_t de;
  uint32_t dis;
  uint32_t pr;
  uint32_t t;
  int8_t r;
  uint8_t ch;
  uint8_t src[6];
  uint8_t bssid[6];

  noInterrupts();

  de = deauthPackets;
  dis = disassocPackets;
  pr = probeReqPackets;
  t = totalPackets;
  r = lastRssi;
  ch = lastChannelSeen;

  for (int i = 0; i < 6; i++) {
    src[i] = lastSrcMac[i];
    bssid[i] = lastBssidMac[i];
  }

  interrupts();

  uiClear();
  topBar("Evidence Log");

  display.setCursor(0, 12);
  display.print("Risk:");
  display.print(riskText());
  display.print(" CH:");
  display.println(ch);

  display.setCursor(0, 22);
  display.print("De:");
  display.print(de);
  display.print(" Ds:");
  display.print(dis);
  display.print(" Pr:");
  display.println(pr);

  display.setCursor(0, 32);
  display.print("Total:");
  display.print(t);
  display.print(" R:");
  display.println(r);

  display.setCursor(0, 42);
  display.print("S:");
  display.print(shortMac(src));
  display.print(" B:");
  display.println(shortMac(bssid));

  bottomHint("D:Reset L:Back");
  display.display();
}

void showOledTest() {
  static int x = 0;
  static int y = 12;
  static int dx = 3;
  static int dy = 2;
  static unsigned long frame = 0;

  uiClear();
  topBar("OLED Test");

  display.drawRect(0, 12, 128, 40, SSD1306_WHITE);
  display.fillRect(x, y, 10, 10, SSD1306_WHITE);

  x += dx;
  y += dy;

  if (x <= 1 || x >= 117) dx = -dx;
  if (y <= 13 || y >= 41) dy = -dy;

  display.setCursor(4, 44);
  display.print("Frame:");
  display.print(frame++);

  bottomHint("L:Back");
  display.display();
}

void showDeviceInfo() {
  uiClear();
  topBar("Device Info");

  display.setCursor(0, 14);
  display.print("Mode:");

  if (snifferRunning) display.println("MONITOR");
  else display.println("STATION");

  display.setCursor(0, 24);
  display.print("MAC:");
  display.println(WiFi.macAddress());

  display.setCursor(0, 36);
  display.print("Heap:");
  display.print(ESP.getFreeHeap());
  display.println("B");

  display.setCursor(0, 46);
  display.print("Up:");
  display.print(millis() / 1000);
  display.println("s");

  bottomHint("L:Back");
  display.display();
}

void showBatteryRaw() {
  int raw = analogRead(A0);

  uiClear();
  topBar("Battery Raw");

  display.setCursor(0, 16);
  display.print("A0 raw:");
  display.println(raw);

  display.setCursor(0, 30);
  display.println("Board dependent");

  display.setCursor(0, 42);
  display.println("Calibrate later");

  bottomHint("L:Back");
  display.display();
}

void showRestart() {
  uiClear();
  topBar("Restart");

  display.setCursor(0, 22);
  display.println("Double press");

  display.setCursor(0, 36);
  display.println("to restart device");

  bottomHint("D:Restart L:Back");
  display.display();
}

void showAbout() {
  uiClear();
  topBar("About");

  display.setCursor(0, 14);
  display.println("ESPNoted v1.0");

  display.setCursor(0, 26);
  display.println("ESP8266 OLED");

  display.setCursor(0, 38);
  display.println("Network console");

  display.setCursor(0, 48);
  display.println("Passive monitor");

  bottomHint("L:Back");
  display.display();
}

void drawScreen() {
  if (screen == SCREEN_SPLASH) showSplash();
  else if (screen == SCREEN_MENU) showMenu();

  else if (screen == SCREEN_NETWORK_SCAN) showNetworkScan();
  else if (screen == SCREEN_ACCESS_POINTS) showAccessPoints();
  else if (screen == SCREEN_AP_DETAILS) showAPDetails();
  else if (screen == SCREEN_SIGNAL_TRACKER) showSignalTracker();
  else if (screen == SCREEN_CHANNELS) showChannels();
  else if (screen == SCREEN_OPEN_NETWORKS) showOpenNetworks();
  else if (screen == SCREEN_HIDDEN_NETWORKS) showHiddenNetworks();
  else if (screen == SCREEN_ROGUE_AP_WATCH) showRogueAPWatch();

  else if (screen == SCREEN_PACKET_MONITOR) showPacketMonitor();
  else if (screen == SCREEN_DEAUTH_MONITOR) showDeauthMonitor();
  else if (screen == SCREEN_PROBE_MONITOR) showProbeMonitor();
  else if (screen == SCREEN_EVIDENCE_LOG) showEvidenceLog();

  else if (screen == SCREEN_OLED_TEST) showOledTest();
  else if (screen == SCREEN_DEVICE_INFO) showDeviceInfo();
  else if (screen == SCREEN_BATTERY_RAW) showBatteryRaw();
  else if (screen == SCREEN_RESTART) showRestart();
  else if (screen == SCREEN_ABOUT) showAbout();
}

// =======================================================
// NAVIGATION
// =======================================================

void enterMenuItem() {
  if (menuIndex == 0) {
    runWiFiScan();
    screen = SCREEN_NETWORK_SCAN;
  } else if (menuIndex == 1) {
    if (!hasScanned) runWiFiScan();
    screen = SCREEN_ACCESS_POINTS;
  } else if (menuIndex == 2) {
    if (!hasScanned) runWiFiScan();
    screen = SCREEN_AP_DETAILS;
  } else if (menuIndex == 3) {
    if (!hasScanned) runWiFiScan();
    screen = SCREEN_SIGNAL_TRACKER;
  } else if (menuIndex == 4) {
    if (!hasScanned) runWiFiScan();
    screen = SCREEN_CHANNELS;
  } else if (menuIndex == 5) {
    if (!hasScanned) runWiFiScan();
    screen = SCREEN_OPEN_NETWORKS;
  } else if (menuIndex == 6) {
    if (!hasScanned) runWiFiScan();
    screen = SCREEN_HIDDEN_NETWORKS;
  } else if (menuIndex == 7) {
    if (!hasScanned) runWiFiScan();
    screen = SCREEN_ROGUE_AP_WATCH;
  } else if (menuIndex == 8) {
    startSniffer(SNIFFER_PACKET_MONITOR);
    screen = SCREEN_PACKET_MONITOR;
  } else if (menuIndex == 9) {
    startSniffer(SNIFFER_DEAUTH_MONITOR);
    screen = SCREEN_DEAUTH_MONITOR;
  } else if (menuIndex == 10) {
    startSniffer(SNIFFER_PROBE_MONITOR);
    screen = SCREEN_PROBE_MONITOR;
  } else if (menuIndex == 11) {
    screen = SCREEN_EVIDENCE_LOG;
  } else if (menuIndex == 12) {
    stopSniffer();
    screen = SCREEN_OLED_TEST;
  } else if (menuIndex == 13) {
    screen = SCREEN_DEVICE_INFO;
  } else if (menuIndex == 14) {
    screen = SCREEN_BATTERY_RAW;
  } else if (menuIndex == 15) {
    stopSniffer();
    screen = SCREEN_RESTART;
  } else if (menuIndex == 16) {
    screen = SCREEN_ABOUT;
  }

  drawScreen();
}

void handleShortPress() {
  if (screen == SCREEN_MENU) {
    menuIndex++;

    if (menuIndex >= MENU_COUNT) {
      menuIndex = 0;
      menuTop = 0;
    }

    drawScreen();
    return;
  }

  if (
    screen == SCREEN_ACCESS_POINTS ||
    screen == SCREEN_AP_DETAILS ||
    screen == SCREEN_SIGNAL_TRACKER
  ) {
    if (hasScanned && networkCount > 0) {
      selectedNetwork++;

      if (selectedNetwork >= networkCount) {
        selectedNetwork = 0;
        browserTop = 0;
      }
    }

    drawScreen();
    return;
  }

  if (
    screen == SCREEN_PACKET_MONITOR ||
    screen == SCREEN_DEAUTH_MONITOR ||
    screen == SCREEN_PROBE_MONITOR
  ) {
    autoHop = false;
    nextChannel();
    drawScreen();
    return;
  }
}

void handleDoublePress() {
  if (screen == SCREEN_MENU) {
    enterMenuItem();
    return;
  }

  if (
    screen == SCREEN_NETWORK_SCAN ||
    screen == SCREEN_CHANNELS ||
    screen == SCREEN_OPEN_NETWORKS ||
    screen == SCREEN_HIDDEN_NETWORKS ||
    screen == SCREEN_SIGNAL_TRACKER
  ) {
    runWiFiScan();
    drawScreen();
    return;
  }

  if (screen == SCREEN_ACCESS_POINTS) {
    screen = SCREEN_AP_DETAILS;
    drawScreen();
    return;
  }

  if (screen == SCREEN_AP_DETAILS) {
    setTrustedAPFromSelection();

    uiClear();
    topBar("Trusted AP");
    display.setCursor(0, 22);
    display.println("Trusted AP saved");
    display.setCursor(0, 36);
    display.println(shortText(trustedSSID, 18));
    display.display();
    delay(900);

    drawScreen();
    return;
  }

  if (screen == SCREEN_ROGUE_AP_WATCH) {
    runWiFiScan();
    screen = SCREEN_ROGUE_AP_WATCH;
    drawScreen();
    return;
  }

  if (
    screen == SCREEN_PACKET_MONITOR ||
    screen == SCREEN_DEAUTH_MONITOR ||
    screen == SCREEN_PROBE_MONITOR
  ) {
    autoHop = !autoHop;
    drawScreen();
    return;
  }

  if (screen == SCREEN_EVIDENCE_LOG) {
    resetStats();
    drawScreen();
    return;
  }

  if (screen == SCREEN_RESTART) {
    uiClear();
    topBar("Restart");
    display.setCursor(0, 28);
    display.println("Restarting...");
    display.display();
    delay(700);
    ESP.restart();
  }
}

void handleLongPress() {
  if (
    screen == SCREEN_PACKET_MONITOR ||
    screen == SCREEN_DEAUTH_MONITOR ||
    screen == SCREEN_PROBE_MONITOR
  ) {
    stopSniffer();
    screen = SCREEN_MENU;
    drawScreen();
    return;
  }

  if (screen != SCREEN_MENU) {
    screen = SCREEN_MENU;
    drawScreen();
    return;
  }

  uiClear();
  topBar("ESPNoted");
  display.setCursor(0, 28);
  display.println("Already home");
  display.display();
  delay(700);
  drawScreen();
}

// =======================================================
// SETUP / LOOP
// =======================================================

void setup() {
  Serial.begin(115200);
  delay(200);

  pinMode(BUTTON_PIN, INPUT_PULLUP);

  Wire.begin(OLED_SDA, OLED_SCL);
  Wire.setClock(400000);

  if (!display.begin(SSD1306_SWITCHCAPVCC, OLED_ADDR)) {
    Serial.println("OLED failed. Try OLED_ADDR 0x3D.");

    while (true) {
      delay(1000);
    }
  }

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(300);

  showSplash();
  drawScreen();

  Serial.println();
  Serial.println("ESPNoted v1.0 ready");
  Serial.println("Short  = Down / Next / Next channel");
  Serial.println("Double = Enter / Rescan / Select / Toggle");
  Serial.println("Long   = Back / Exit");
}

void loop() {
  ButtonEvent event = readButton();

  if (event == BTN_SHORT) {
    Serial.println("BTN SHORT");
    handleShortPress();
  } else if (event == BTN_DOUBLE) {
    Serial.println("BTN DOUBLE");
    handleDoublePress();
  } else if (event == BTN_LONG) {
    Serial.println("BTN LONG");
    handleLongPress();
  }

  if (snifferRunning) {
    unsigned long now = millis();

    if (autoHop && now - lastHopTime >= HOP_MS) {
      lastHopTime = now;
      nextChannel();
    }

    if (now - lastRateTime >= RATE_MS) {
      lastRateTime = now;
      updateRates();
    }

    if (
      now - lastScreenUpdate >= SNIFFER_SCREEN_MS &&
      (
        screen == SCREEN_PACKET_MONITOR ||
        screen == SCREEN_DEAUTH_MONITOR ||
        screen == SCREEN_PROBE_MONITOR ||
        screen == SCREEN_EVIDENCE_LOG
      )
    ) {
      lastScreenUpdate = now;
      drawScreen();
    }
  }

  if (screen == SCREEN_OLED_TEST) {
    if (millis() - lastOledAnim >= OLED_ANIM_MS) {
      lastOledAnim = millis();
      drawScreen();
    }
  }

  static unsigned long lastDeviceRefresh = 0;

  if (
    (screen == SCREEN_DEVICE_INFO || screen == SCREEN_BATTERY_RAW) &&
    millis() - lastDeviceRefresh >= 1000
  ) {
    lastDeviceRefresh = millis();
    drawScreen();
  }

  yield();
}