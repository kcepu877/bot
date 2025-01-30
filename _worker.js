import { connect } from "cloudflare:sockets";

// Variables
let cachedProxyList = [];
let proxyIP = "";
const DEFAULT_PROXY_BANK_URL = "https://cf.cepu.us.kg/update_proxyip.txt";
const TELEGRAM_BOT_TOKEN = '7826108422:AAEmQiVx2TvdAZnvpKw2zJZUvv8fOEGruW0';
const TELEGRAM_API_URL = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}`;
const APICF = 'https://ipcf.rmtq.fun/json/';
const FAKE_HOSTNAME = 'user.kere.us.kg';

// Fungsi untuk menangani `/active`
async function handleActive(request) {
  const host = request.headers.get('Host');
  const webhookUrl = `https://${host}/webhook`;

  const response = await fetch(`${TELEGRAM_API_URL}/setWebhook`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: webhookUrl }),
  });

  if (response.ok) {
    return new Response('Webhook set successfully', { status: 200 });
  }
  return new Response('Failed to set webhook', { status: 500 });
}

// Fungsi untuk menangani `/webhook`
async function handleWebhook(request) {
  const update = await request.json();

  if (update.callback_query) {
    return await handleCallbackQuery(update.callback_query);
  } else if (update.message) {
    return await handleMessage(update.message);
  }

  return new Response('OK', { status: 200 });
}

// Routing utama sebelum mencapai handler default
async function routeRequest(request) {
  const url = new URL(request.url);

  // Tangani rute khusus di luar handler utama
  if (url.pathname === '/active') {
    return await handleActive(request);
  }

  if (url.pathname === '/webhook' && request.method === 'POST') {
    return await handleWebhook(request);
  }

  // Jika tidak ada rute yang cocok, teruskan ke handler utama
  return null;
}

// Export utama, tidak diubah
export default {
  async fetch(request, env, ctx) {
    try {
      // Periksa rute khusus sebelum melanjutkan ke handler utama
      const routeResponse = await routeRequest(request);
      if (routeResponse) {
        return routeResponse;
      }

      // Handler utama tetap tidak terganggu
      const url = new URL(request.url);
      const upgradeHeader = request.headers.get("Upgrade");

      if (upgradeHeader === "websocket") {
        const proxyMatch = url.pathname.match(/^\/(.+[:=-]\d+)$/);

        if (proxyMatch) {
          proxyIP = proxyMatch[1];
          return await websockerHandler(request);
        }
      }

      switch (url.pathname) {
        default:
          const hostname = request.headers.get("Host");
          const result = getAllConfig(hostname, await getProxyList(env, true));
          return new Response(result, {
            status: 200,
            headers: { "Content-Type": "text/html;charset=utf-8" },
          });
      }
    } catch (err) {
      return new Response(`An error occurred: ${err.toString()}`, {
        status: 500,
      });
    }
  },
};

// Tambahkan fungsi pendukung lainnya di bawah ini


async function handleCallbackQuery(callbackQuery) {
  const callbackData = callbackQuery.data;
  const chatId = callbackQuery.message.chat.id;

  const myhostname = FAKE_HOSTNAME; // Menggunakan myhostname sebagai default host

  if (callbackData.startsWith('create_vless')) {
    const [_, ip, port, isp] = callbackData.split('|');
    await handleVlessCreation(chatId, ip, port, isp, myhostname);
  } else if (callbackData.startsWith('create_trojan')) {
    const [_, ip, port, isp] = callbackData.split('|');
    await handleTrojanCreation(chatId, ip, port, isp, myhostname);
  } else if (callbackData.startsWith('create_ss')) {
    const [_, ip, port, isp] = callbackData.split('|');
    await handleShadowSocksCreation(chatId, ip, port, isp, myhostname);
  }

  return new Response('OK', { status: 200 });
}

async function handleMessage(message) {
  const chatId = message.chat.id;
  const text = message.text;

  if (isValidIPPortFormat(text)) {
    const [ip, port] = text.split(':');
    const result = await checkIPPort(ip, port, chatId);
    if (result) await sendTelegramMessage(chatId, result);
  } else {
    await sendTelegramMessage(chatId, '⚠️ Format tidak valid. Gunakan format IP:Port (contoh: 192.168.1.1:80).');
  }

  return new Response('OK', { status: 200 });
}

function isValidIPPortFormat(input) {
  const regex = /^(\d{1,3}\.){3}\d{1,3}:\d{1,5}$/;
  return regex.test(input);
}

// Check IP and Port status
async function checkIPPort(ip, port, chatId) {
  try {
    const response = await fetch(`${APICF}?ip=${ip}:${port}`);
    if (!response.ok) throw new Error(`API Error: ${response.statusText}`);

    const data = await response.json();
    const status = data.STATUS === "✔ AKTIF ✔" ? "✅ Aktif" : "❌ Tidak Aktif";

    const resultMessage = `
🌐 **Hasil Cek IP dan Port**:
━━━━━━━━━━━━━━━━━━━━━━━
📍 **IP**: ${data.IP}
🔌 **Port**: ${data.PORT}
📡 **ISP**: ${data.ISP}
🏢 **ASN**: ${data.ASN}
🌆 **Kota**: ${data.KOTA}
📶 **Status**: ${status}
━━━━━━━━━━━━━━━━━━━━━━━
    `;
    await sendTelegramMessage(chatId, resultMessage);

    if (status === "✅ Aktif") {
      await sendInlineKeyboard(chatId, data.IP, data.PORT, data.ISP);
    }
  } catch (error) {
    return `⚠️ Terjadi kesalahan saat memeriksa IP dan port: ${error.message}`;
  }
}

async function handleShadowSocksCreation(chatId, ip, port, isp, myhostname) {
  const ssTls = `ss://${btoa(`none:${crypto.randomUUID()}`)}@${myhostname}:443?encryption=none&type=ws&host=${myhostname}&path=%2F${ip}-${port}&security=tls&sni=${myhostname}#${isp}`;
  const ssNTls = `ss://${btoa(`none:${crypto.randomUUID()}`)}@${myhostname}:80?encryption=none&type=ws&host=${myhostname}&path=%2F${ip}-${port}&security=none&sni=${myhostname}#${isp}`;

  const proxies = `
proxies:
- name: ${isp}
  server: ${myhostname}
  port: 443
  type: ss
  cipher: none
  password: ${crypto.randomUUID()}
  plugin: v2ray-plugin
  client-fingerprint: chrome
  udp: true
  plugin-opts:
    mode: websocket
    host: ${myhostname}
    path: /${ip}-${port}
    tls: true
    mux: false
    skip-cert-verify: true
`;

  const message = `
Success Create ShadowSocks \`${isp}\` \n⚜️ \`${ip}:${port}\` ⚜️

🔗 **Links ShadowSocks**:\n
1️⃣ **TLS**: \`${ssTls}\`
2️⃣ **Non-TLS**: \`${ssNTls}\`

📄 **Proxies Config**:
\`\`\`
${proxies}
\`\`\`
  `;

  // Kirim pesan melalui Telegram
  await sendTelegramMessage(chatId, message);
}


// Generate VLESS configuration
// VLESS Creation Function
async function handleVlessCreation(chatId, ip, port, isp, myhostname) {
  const path = `/${ip}-${port}`;
  const vlessTLS = `vless://${crypto.randomUUID()}@${myhostname}:443?path=${encodeURIComponent(path)}&security=tls&host=${myhostname}&type=ws&sni=${myhostname}#${isp}`;
  const vlessNTLS = `vless://${crypto.randomUUID()}@${myhostname}:80?path=${encodeURIComponent(path)}&security=none&host=${myhostname}&type=ws&sni=${myhostname}#${isp}`;

  const message = `
Success Create VLESS \`${isp}\` \n⚜️ \`${ip}:${port}\` ⚜️

🔗 **Links Vless**:\n
1️⃣ **TLS**: \`${vlessTLS}\`
2️⃣ **Non-TLS**: \`${vlessNTLS}\`

📄 **Proxies Config**:
\`\`\`
proxies:
- name: ${isp}
  server: ${myhostname}
  port: 443
  type: vless
  uuid: ${crypto.randomUUID()}
  cipher: auto
  tls: true
  udp: true
  skip-cert-verify: true
  network: ws
  servername: ${myhostname}
  ws-opts:
    path: ${path}
    headers:
      Host: ${myhostname}
\`\`\`
  `;

  await sendTelegramMessage(chatId, message);
}

// Trojan Creation Function
async function handleTrojanCreation(chatId, ip, port, isp, myhostname) {
  const path = `/${ip}-${port}`;
  const trojanTLS = `trojan://${crypto.randomUUID()}@${myhostname}:443?path=${encodeURIComponent(myhostname)}&security=tls&host=${myhostname}&type=ws&sni=${myhostname}#${isp}`;
  const trojanNTLS = `trojan://${crypto.randomUUID()}@${myhostname}:80?path=${encodeURIComponent(myhostname)}&security=none&host=${myhostname}&type=ws&sni=${myhostname}#${isp}`;

  const message = `
Success Create TROJAN \`${isp}\` \n⚜️ \`${ip}:${port}\` ⚜️

🔗 **Links Trojan**:\n
1️⃣ **TLS**: \`${trojanTLS}\`
2️⃣ **Non-TLS**: \`${trojanNTLS}\`

📄 **Proxies Config**:
\`\`\`
proxies:
- name: ${isp}
  server: ${myhostname}
  port: 443
  type: trojan
  password: ${crypto.randomUUID()}
  udp: true
  network: ws
  sni: ${myhostname}
  ws-opts:
    path: ${path}
    headers:
      Host: ${myhostname}
\`\`\`
  `;

  await sendTelegramMessage(chatId, message);
}

async function sendTelegramMessage(chatId, text) {
  const response = await fetch(`${TELEGRAM_API_URL}/sendMessage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      chat_id: chatId,
      text: text,
      parse_mode: 'Markdown', // Gunakan Markdown untuk format teks
    }),
  });

  if (!response.ok) {
    console.error('Failed to send message:', await response.text());
  }
}

/**
 * Fungsi untuk mengirim inline keyboard
 */
async function sendInlineKeyboard(chatId, ip, port, isp) {
  const response = await fetch(`${TELEGRAM_API_URL}/sendMessage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      chat_id: chatId,
      text: '✅ IP dan Port Aktif. Pilih opsi berikut untuk membuat link:',
      reply_markup: {
        inline_keyboard: [
          [
            { text: 'Create VLESS', callback_data: `create_vless|${ip}|${port}|${isp}` },
            { text: 'Create Trojan', callback_data: `create_trojan|${ip}|${port}|${isp}` },
          ],
          [
            { text: 'Create ShadowSocks', callback_data: `create_ss|${ip}|${port}|${isp}` },
          ],
        ],
      },
    }),
  });

  if (!response.ok) {
    console.error('Failed to send inline keyboard:', await response.text());
  }
}
// Constant
const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

// Fetch proxy list from external source
async function getProxyList(env, forceReload = false) {
  if (!cachedProxyList.length || forceReload) {
    const proxyBankUrl = env.PROXY_BANK_URL || DEFAULT_PROXY_BANK_URL;
    const proxyBankResponse = await fetch(proxyBankUrl);

    if (proxyBankResponse.ok) {
      const proxyLines = (await proxyBankResponse.text()).split("\n").filter(Boolean);
      cachedProxyList = proxyLines.map((line) => {
        const [proxyIP, proxyPort, country, org] = line.split(",");
        return { proxyIP, proxyPort, country, org };
      });
    }
  }
  return cachedProxyList;
}

function getAllConfig(hostName, proxyList) {
  const proxyListElements = proxyList
    .map(({ proxyIP, proxyPort, country, org }, index) => {
      const vlessTls = `vless://${crypto.randomUUID()}@${hostName}:443?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F${proxyIP}%3D${proxyPort}#(${country})%20${org}`;
      const vlessNTls = `vless://${crypto.randomUUID()}@${hostName}:80?encryption=none&security=none&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F${proxyIP}%3D${proxyPort}#(${country})%20${org}`;
      const trojanTls = `trojan://${crypto.randomUUID()}@${hostName}:443?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F${proxyIP}%3D${proxyPort}#(${country})%20${org}`;
      const trojanNTls = `trojan://${crypto.randomUUID()}@${hostName}:80?encryption=none&security=none&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F${proxyIP}%3D${proxyPort}#(${country})%20${org}`;
      const ssTls = `ss://${btoa(`none:${crypto.randomUUID()}`)}@${hostName}:443?encryption=none&type=ws&host=${hostName}&path=%2F${proxyIP}%3D${proxyPort}&security=tls&sni=${hostName}#${country}%20${org}`;
      const ssNTls = `ss://${btoa(`none:${crypto.randomUUID()}`)}@${hostName}:80?encryption=none&type=ws&host=${hostName}&path=%2F${proxyIP}%3D${proxyPort}&security=none&sni=${hostName}#${country}%20${org}`;

      // Gabungkan semua konfigurasi menjadi satu string
      const allconfigs = [
        ssTls,
        ssNTls,
        vlessTls,
        vlessNTls,
        trojanTls,
        trojanNTls,
      ].join('\n\n');

      // Encode string untuk digunakan di fungsi JavaScript
      const encodedAllconfigs = encodeURIComponent(allconfigs);

      return `
        <div class="content ${index === 0 ? "active" : ""}">
          <h2>VLESS TROJAN SHADOWSOCKS</h2><br>
          <h2>CLOUDFLARE</h2><br>
          <h2>Free and Unlimited</h2><br>
          <hr class="config-divider"/>
          <center><h1>${country} (${org})</h1></center>
          <center><h1>${proxyIP}:${proxyPort}</h1></center>
          <hr class="config-divider" />
          <h2>VLESS</h2>
          <pre>${vlessTls}</pre>
          <button onclick="copyToClipboard('${vlessTls}')">Copy Vless TLS</button>
          <pre>${vlessNTls}</pre>
          <button onclick="copyToClipboard('${vlessNTls}')">Copy Vless N-TLS</button>
          <hr class="config-divider" />
          <h2>TROJAN</h2>
          <pre>${trojanTls}</pre>
          <button onclick="copyToClipboard('${trojanTls}')">Copy Trojan TLS</button>
          <pre>${trojanNTls}</pre>
          <button onclick="copyToClipboard('${trojanNTls}')">Copy Trojan N-TLS</button>
          <hr class="config-divider" />
          <h2>SHADOWSOCKS</h2>
          <pre>${ssTls}</pre>
          <button onclick="copyToClipboard('${ssTls}')">Copy Shadowsocks TLS</button>
          <pre>${ssNTls}</pre>
          <button onclick="copyToClipboard('${ssNTls}')">Copy Shadowsocks N-TLS</button>
          <hr class="config-divider" />
          <h2>All Configs</h2>
          <center><button onclick="copyToClipboard(decodeURIComponent('${encodedAllconfigs}'))">Copy All Configs</button></center>
          <hr class="config-divider" />          
        </div>`;
    })
    .join("");
  return `
    <html>
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">
        <title>Vless | Trojan | Shadowsocks | AFRCloud | CloudFlare</title>
        <style>
  html, body {
    height: 100%;
    width: 100%;
    overflow: hidden;
    background-color: #1a1a1a;
    font-family: 'Roboto', Arial, sans-serif;
    margin: 0;
  }
  body {
    display: flex;
    background: url('https://raw.githubusercontent.com/bitzblack/ip/refs/heads/main/shubham-dhage-5LQ_h5cXB6U-unsplash.jpg') no-repeat center center fixed;
    background-size: cover;
    justify-content: center;
    align-items: center;
  }
  .popup {
    width: 100vw;
    height: 90vh;
    border-radius: 15px;
    background-color: rgba(0, 0, 0, 0.9);
    backdrop-filter: blur(8px);
    display: grid;
    grid-template-columns: 1.5fr 3fr;
    box-shadow: 0px 10px 20px rgba(255, 223, 0, 0.5); /* Efek kuning */
    overflow: hidden;
    animation: popupEffect 1s ease-in-out;
  }
  @keyframes popupEffect {
    0% { transform: scale(0.8); opacity: 0; }
    100% { transform: scale(1); opacity: 1; }
  }
  .tabs {
    background-color: #2a2a2a;
    padding: 10px;
    display: flex;
    flex-direction: column;
    gap: 8px;
    overflow-y: auto;
    overflow-x: hidden;
    border-right: 2px solid #FFD700; /* Warna kuning */
    box-shadow: inset 0 0 10px rgba(255, 223, 0, 0.3); /* Glow kuning */
  }
  .author-link {
    position: absolute;
    bottom: 10px;
    right: 10px;
    font-weight: bold;
    font-style: italic;
    color: #FFD700; /* Warna kuning */
    font-size: 12px;
    text-decoration: none;
    z-index: 10;
  }
  .author-link:hover {
    color: #FFF700; /* Kuning lebih terang */
    text-shadow: 0px 0px 10px rgba(255, 223, 0, 0.7);
  }
  label {
    font-size: 12px;
    cursor: pointer;
    color: #FFD700; /* Warna kuning */
    padding: 10px;
    background-color: #333;
    border-radius: 8px;
    text-align: left;
    transition: background-color 0.3s ease, transform 0.3s ease;
    box-shadow: 0px 4px 6px rgba(255, 223, 0, 0.3); /* Glow kuning */
    white-space: normal;
    overflow-wrap: break-word;
  }
  label:hover {
    background-color: #FFD700; /* Kuning */
    color: #111;
    transform: translateY(-3px);
    box-shadow: 0px 8px 12px rgba(255, 223, 0, 0.7);
  }
  input[type="radio"] {
    display: none;
  }
  .tab-content {
    padding: 20px;
    overflow-y: auto;
    color: #FFFACD; /* Kuning pucat */
    font-size: 14px;
    background-color: #222;
    height: 100%;
    box-sizing: border-box;
    border-radius: 10px;
    box-shadow: inset 0 0 20px rgba(255, 223, 0, 0.2);
  }
  .content {
    display: none;
    padding-right: 15px;
  }
  .content.active {
    display: block;
    animation: fadeIn 0.5s ease;
  }
  @keyframes fadeIn {
    from { opacity: 0; }
    to { opacity: 1; }
  }
  h1 {
    font-size: 18px;
    color: #FFD700; /* Kuning */
    margin-bottom: 10px;
    text-shadow: 0px 0px 10px rgba(255, 223, 0, 0.5);
  }
  h2 {
    font-size: 22px;
    color: #FFD700; /* Kuning */
    text-align: center;
    text-shadow: 0px 0px 15px rgba(255, 223, 0, 0.7);
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 8px;
  }
  pre {
    background-color: rgba(50, 50, 50, 0.8);
    padding: 10px;
    border-radius: 8px;
    font-size: 12px;
    white-space: pre-wrap;
    word-wrap: break-word;
    color: #FFD700; /* Kuning */
    border: 1px solid #FFD700;
    box-shadow: 0px 4px 8px rgba(255, 223, 0, 0.4);
  }
  .config-divider {
    border: none;
    height: 1px;
    background: linear-gradient(to right, transparent, #FFD700, transparent);
    margin: 40px 0;
  }
  .config-description {
    font-weight: bold;
    font-style: italic;
    color: #FFD700; /* Kuning */
    font-size: 14px;
    text-align: justify;
    margin: 0 10px; /* Tambahkan margin kiri-kanan agar tidak terlalu mepet */
  }
  button {
    padding: 8px 12px;
    border: none;
    border-radius: 5px;
    background-color: #FFD700;
    color: #111;
    cursor: pointer;
    font-weight: bold;
    display: block;
    text-align: left;
    box-shadow: 0px 4px 6px rgba(255, 223, 0, 0.5);
    transition: background-color 0.3s ease, transform 0.3s ease;
  }
  button:hover {
    background-color: #FFF700; /* Kuning lebih terang */
    transform: translateY(-3px);
    box-shadow: 0px 8px 12px rgba(255, 223, 0, 0.8);
  }
  #search {
    background: #333;
    color: #FFD700;
    border: 1px solid #FFD700;
    border-radius: 6px;
    padding: 5px;
    margin-bottom: 10px;
    width: 100%;
    box-shadow: 0px 0px 10px rgba(255, 223, 0, 0.3);
  }
  #search::placeholder {
    color: #FFD700;
  }
  .watermark {
    position: absolute;
    bottom: 10px;
    left: 50%;
    transform: translateX(-50%);
    font-size: 0.8rem;
    color: rgba(255, 255, 255, 0.5);
    text-shadow: 1px 1px 2px rgba(0, 0, 0, 0.5);
    font-weight: bold;
    text-align: center;
  }

  .watermark a {
    color: #e74c3c; /* Red */
    text-decoration: none;
    font-weight: bold;
}

  .watermark a:hover {
    color: #e74c3c; /* Red */
}

  @media (max-width: 768px) {
    .header h1 { font-size: 32px; }
    .config-section h3 { font-size: 24px; }
    .config-block h4 { font-size: 20px; }
  }
</style>
      </head>
      <body>
        <div class="popup">
          <div class="tabs">
            <input type="text" id="search" placeholder="Search by Country" oninput="filterTabs()">
            ${proxyList
              .map(
                ({ country, org }, index) => `
                  <input type="radio" id="tab${index}" name="tab" ${index === 0 ? "checked" : ""}>
                  <label for="tab${index}" class="tab-label" data-country="${country.toLowerCase()}">${country} - ${org}</label>
                `
              )
              .join("")}
          </div>
          <div class="tab-content">${proxyListElements}</div>
          <a href="https://t.me/Noir7R" class="watermark" target="_blank">@Noir7R</a>
        </div>
         <script>
          function filterTabs() {
            const query = document.getElementById('search').value.toLowerCase();
            const labels = document.querySelectorAll('.tab-label');
            labels.forEach(label => {
              const isVisible = label.dataset.country.includes(query);
              label.style.display = isVisible ? "block" : "none";
            });
          }

          function copyToClipboard(text) {
      navigator.clipboard.writeText(text)
        .then(() => {
          displayAlert("Successfully copied to clipboard!", '#FFD700');
        })
        .catch((err) => {
          displayAlert("Failed to copy to clipboard: " + err, '#cc2222');
        });
    }
    function displayAlert(message, backgroundColor) {
      const alertBox = document.createElement('div');
      alertBox.textContent = message;
      Object.assign(alertBox.style, {
          position: 'fixed',
          top: '20px',
          left: '50%',
          transform: 'translateX(-50%)',
          backgroundColor: backgroundColor,
          color: '#222',
          padding: '5px 10px',
          borderRadius: '5px',
          boxShadow: '0 4px 6px rgba(0,0,0,0.2)',
          opacity: '0',
          transition: 'opacity 0.5s ease-in-out',
          zIndex: '1000'
      });
      document.body.appendChild(alertBox);

      requestAnimationFrame(() => {
          alertBox.style.opacity = '1';
      });

      setTimeout(() => {
          alertBox.style.opacity = '0';
          setTimeout(() => {
              document.body.removeChild(alertBox);
          }, 500);
      }, 2000);
    }

          document.querySelectorAll('input[name="tab"]').forEach((tab, index) => {
            tab.addEventListener('change', () => {
              document.querySelectorAll('.content').forEach((content, idx) => {
                content.classList.toggle("active", idx === index);
              });
            });
          });
        </script>
      </body>
    </html>
  `;
}


async function websockerHandler(request) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);

  webSocket.accept();

  let addressLog = "";
  let portLog = "";
  const log = (info, event) => {
    console.log(`[${addressLog}:${portLog}] ${info}`, event || "");
  };
  const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";

  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

  let remoteSocketWrapper = {
    value: null,
  };
  let udpStreamWrite = null;
  let isDNS = false;

  readableWebSocketStream
    .pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          if (isDNS && udpStreamWrite) {
            return udpStreamWrite(chunk);
          }
          if (remoteSocketWrapper.value) {
            const writer = remoteSocketWrapper.value.writable.getWriter();
            await writer.write(chunk);
            writer.releaseLock();
            return;
          }

          const protocol = await protocolSniffer(chunk);
          let protocolHeader;

          if (protocol === "Trojan") {
            protocolHeader = parseTrojanHeader(chunk);
          } else if (protocol === "VLESS") {
            protocolHeader = parseVlessHeader(chunk);
          } else if (protocol === "Shadowsocks") {
            protocolHeader = parseShadowsocksHeader(chunk);
          } else {
            parseVmessHeader(chunk);
            throw new Error("Unknown Protocol!");
          }

          addressLog = protocolHeader.addressRemote;
          portLog = `${protocolHeader.portRemote} -> ${protocolHeader.isUDP ? "UDP" : "TCP"}`;

          if (protocolHeader.hasError) {
            throw new Error(protocolHeader.message);
          }

          if (protocolHeader.isUDP) {
            if (protocolHeader.portRemote === 53) {
              isDNS = true;
            } else {
              throw new Error("UDP only support for DNS port 53");
            }
          }

          if (isDNS) {
            const { write } = await handleUDPOutbound(webSocket, protocolHeader.version, log);
            udpStreamWrite = write;
            udpStreamWrite(protocolHeader.rawClientData);
            return;
          }

          handleTCPOutBound(
            remoteSocketWrapper,
            protocolHeader.addressRemote,
            protocolHeader.portRemote,
            protocolHeader.rawClientData,
            webSocket,
            protocolHeader.version,
            log
          );
        },
        close() {
          log(`readableWebSocketStream is close`);
        },
        abort(reason) {
          log(`readableWebSocketStream is abort`, JSON.stringify(reason));
        },
      })
    )
    .catch((err) => {
      log("readableWebSocketStream pipeTo error", err);
    });

  return new Response(null, {
    status: 101,
    webSocket: client,
  });
}

async function protocolSniffer(buffer) {
  if (buffer.byteLength >= 62) {
    const trojanDelimiter = new Uint8Array(buffer.slice(56, 60));
    if (trojanDelimiter[0] === 0x0d && trojanDelimiter[1] === 0x0a) {
      if (trojanDelimiter[2] === 0x01 || trojanDelimiter[2] === 0x03 || trojanDelimiter[2] === 0x7f) {
        if (trojanDelimiter[3] === 0x01 || trojanDelimiter[3] === 0x03 || trojanDelimiter[3] === 0x04) {
          return "Trojan";
        }
      }
    }
  }

  const vlessDelimiter = new Uint8Array(buffer.slice(1, 17));
  // Hanya mendukung UUID v4
  if (arrayBufferToHex(vlessDelimiter).match(/^\w{8}\w{4}4\w{3}[89ab]\w{3}\w{12}$/)) {
    return "VLESS";
  }

  return "Shadowsocks"; // default
}

async function handleTCPOutBound(
  remoteSocket,
  addressRemote,
  portRemote,
  rawClientData,
  webSocket,
  responseHeader,
  log
) {
  async function connectAndWrite(address, port) {
    const tcpSocket = connect({
      hostname: address,
      port: port,
    });
    remoteSocket.value = tcpSocket;
    log(`connected to ${address}:${port}`);
    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    return tcpSocket;
  }

  async function retry() {
    const tcpSocket = await connectAndWrite(
      proxyIP.split(/[:=-]/)[0] || addressRemote,
      proxyIP.split(/[:=-]/)[1] || portRemote
    );
    tcpSocket.closed
      .catch((error) => {
        console.log("retry tcpSocket closed error", error);
      })
      .finally(() => {
        safeCloseWebSocket(webSocket);
      });
    remoteSocketToWS(tcpSocket, webSocket, responseHeader, null, log);
  }

  const tcpSocket = await connectAndWrite(addressRemote, portRemote);

  remoteSocketToWS(tcpSocket, webSocket, responseHeader, retry, log);
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
  let readableStreamCancel = false;
  const stream = new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener("message", (event) => {
        if (readableStreamCancel) {
          return;
        }
        const message = event.data;
        controller.enqueue(message);
      });
      webSocketServer.addEventListener("close", () => {
        safeCloseWebSocket(webSocketServer);
        if (readableStreamCancel) {
          return;
        }
        controller.close();
      });
      webSocketServer.addEventListener("error", (err) => {
        log("webSocketServer has error");
        controller.error(err);
      });
      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) {
        controller.error(error);
      } else if (earlyData) {
        controller.enqueue(earlyData);
      }
    },

    pull(controller) {},
    cancel(reason) {
      if (readableStreamCancel) {
        return;
      }
      log(`ReadableStream was canceled, due to ${reason}`);
      readableStreamCancel = true;
      safeCloseWebSocket(webSocketServer);
    },
  });

  return stream;
}

function parseVmessHeader(vmessBuffer) {
  // https://xtls.github.io/development/protocols/vmess.html#%E6%8C%87%E4%BB%A4%E9%83%A8%E5%88%86
}

function parseShadowsocksHeader(ssBuffer) {
  const view = new DataView(ssBuffer);

  const addressType = view.getUint8(0);
  let addressLength = 0;
  let addressValueIndex = 1;
  let addressValue = "";

  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValue = new Uint8Array(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
      break;
    case 3:
      addressLength = new Uint8Array(ssBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 4:
      addressLength = 16;
      const dataView = new DataView(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(":");
      break;
    default:
      return {
        hasError: true,
        message: `Invalid addressType for Shadowsocks: ${addressType}`,
      };
  }

  if (!addressValue) {
    return {
      hasError: true,
      message: `Destination address empty, address type is: ${addressType}`,
    };
  }

  const portIndex = addressValueIndex + addressLength;
  const portBuffer = ssBuffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);
  return {
    hasError: false,
    addressRemote: addressValue,
    addressType: addressType,
    portRemote: portRemote,
    rawDataIndex: portIndex + 2,
    rawClientData: ssBuffer.slice(portIndex + 2),
    version: null,
    isUDP: portRemote == 53,
  };
}

function parseVlessHeader(vlessBuffer) {
  const version = new Uint8Array(vlessBuffer.slice(0, 1));
  let isUDP = false;

  const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];

  const cmd = new Uint8Array(vlessBuffer.slice(18 + optLength, 18 + optLength + 1))[0];
  if (cmd === 1) {
  } else if (cmd === 2) {
    isUDP = true;
  } else {
    return {
      hasError: true,
      message: `command ${cmd} is not support, command 01-tcp,02-udp,03-mux`,
    };
  }
  const portIndex = 18 + optLength + 1;
  const portBuffer = vlessBuffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);

  let addressIndex = portIndex + 2;
  const addressBuffer = new Uint8Array(vlessBuffer.slice(addressIndex, addressIndex + 1));

  const addressType = addressBuffer[0];
  let addressLength = 0;
  let addressValueIndex = addressIndex + 1;
  let addressValue = "";
  switch (addressType) {
    case 1: // For IPv4
      addressLength = 4;
      addressValue = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
      break;
    case 2: // For Domain
      addressLength = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 3: // For IPv6
      addressLength = 16;
      const dataView = new DataView(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(":");
      break;
    default:
      return {
        hasError: true,
        message: `invild  addressType is ${addressType}`,
      };
  }
  if (!addressValue) {
    return {
      hasError: true,
      message: `addressValue is empty, addressType is ${addressType}`,
    };
  }

  return {
    hasError: false,
    addressRemote: addressValue,
    addressType: addressType,
    portRemote: portRemote,
    rawDataIndex: addressValueIndex + addressLength,
    rawClientData: vlessBuffer.slice(addressValueIndex + addressLength),
    version: new Uint8Array([version[0], 0]),
    isUDP: isUDP,
  };
}

function parseTrojanHeader(buffer) {
  const socks5DataBuffer = buffer.slice(58);
  if (socks5DataBuffer.byteLength < 6) {
    return {
      hasError: true,
      message: "invalid SOCKS5 request data",
    };
  }

  let isUDP = false;
  const view = new DataView(socks5DataBuffer);
  const cmd = view.getUint8(0);
  if (cmd == 3) {
    isUDP = true;
  } else if (cmd != 1) {
    throw new Error("Unsupported command type!");
  }

  let addressType = view.getUint8(1);
  let addressLength = 0;
  let addressValueIndex = 2;
  let addressValue = "";
  switch (addressType) {
    case 1: // For IPv4
      addressLength = 4;
      addressValue = new Uint8Array(socks5DataBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(
        "."
      );
      break;
    case 3: // For Domain
      addressLength = new Uint8Array(socks5DataBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(
        socks5DataBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
      );
      break;
    case 4: // For IPv6
      addressLength = 16;
      const dataView = new DataView(socks5DataBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(":");
      break;
    default:
      return {
        hasError: true,
        message: `invalid addressType is ${addressType}`,
      };
  }

  if (!addressValue) {
    return {
      hasError: true,
      message: `address is empty, addressType is ${addressType}`,
    };
  }

  const portIndex = addressValueIndex + addressLength;
  const portBuffer = socks5DataBuffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);
  return {
    hasError: false,
    addressRemote: addressValue,
    addressType: addressType,
    portRemote: portRemote,
    rawDataIndex: portIndex + 4,
    rawClientData: socks5DataBuffer.slice(portIndex + 4),
    version: null,
    isUDP: isUDP,
  };
}

async function remoteSocketToWS(remoteSocket, webSocket, responseHeader, retry, log) {
  let header = responseHeader;
  let hasIncomingData = false;
  await remoteSocket.readable
    .pipeTo(
      new WritableStream({
        start() {},
        async write(chunk, controller) {
          hasIncomingData = true;
          if (webSocket.readyState !== WS_READY_STATE_OPEN) {
            controller.error("webSocket.readyState is not open, maybe close");
          }
          if (header) {
            webSocket.send(await new Blob([header, chunk]).arrayBuffer());
            header = null;
          } else {
            webSocket.send(chunk);
          }
        },
        close() {
          log(`remoteConnection!.readable is close with hasIncomingData is ${hasIncomingData}`);
        },
        abort(reason) {
          console.error(`remoteConnection!.readable abort`, reason);
        },
      })
    )
    .catch((error) => {
      console.error(`remoteSocketToWS has exception `, error.stack || error);
      safeCloseWebSocket(webSocket);
    });
  if (hasIncomingData === false && retry) {
    log(`retry`);
    retry();
  }
}

function base64ToArrayBuffer(base64Str) {
  if (!base64Str) {
    return { error: null };
  }
  try {
    base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
    const decode = atob(base64Str);
    const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
    return { earlyData: arryBuffer.buffer, error: null };
  } catch (error) {
    return { error };
  }
}

function arrayBufferToHex(buffer) {
  return [...new Uint8Array(buffer)].map((x) => x.toString(16).padStart(2, "0")).join("");
}

async function handleUDPOutbound(webSocket, responseHeader, log) {
  let isVlessHeaderSent = false;
  const transformStream = new TransformStream({
    start(controller) {},
    transform(chunk, controller) {
      for (let index = 0; index < chunk.byteLength; ) {
        const lengthBuffer = chunk.slice(index, index + 2);
        const udpPakcetLength = new DataView(lengthBuffer).getUint16(0);
        const udpData = new Uint8Array(chunk.slice(index + 2, index + 2 + udpPakcetLength));
        index = index + 2 + udpPakcetLength;
        controller.enqueue(udpData);
      }
    },
    flush(controller) {},
  });
  transformStream.readable
    .pipeTo(
      new WritableStream({
        async write(chunk) {
          const resp = await fetch("https://1.1.1.1/dns-query", {
            method: "POST",
            headers: {
              "content-type": "application/dns-message",
            },
            body: chunk,
          });
          const dnsQueryResult = await resp.arrayBuffer();
          const udpSize = dnsQueryResult.byteLength;
          const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);
          if (webSocket.readyState === WS_READY_STATE_OPEN) {
            log(`doh success and dns message length is ${udpSize}`);
            if (isVlessHeaderSent) {
              webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
            } else {
              webSocket.send(await new Blob([responseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
              isVlessHeaderSent = true;
            }
          }
        },
      })
    )
    .catch((error) => {
      log("dns udp has error" + error);
    });

  const writer = transformStream.writable.getWriter();

  return {
    write(chunk) {
      writer.write(chunk);
    },
  };
}

function safeCloseWebSocket(socket) {
  try {
    if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
      socket.close();
    }
  } catch (error) {
    console.error("safeCloseWebSocket error", error);
  }
}
