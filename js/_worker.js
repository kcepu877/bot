import { connect } from "cloudflare:sockets";

// Variables
let cachedProxyList = [];
let proxyIP = "";
let apiCheck = 'https://ipcf.rmtq.fun/json/?ip=';

const DEFAULT_PROXY_BANK_URL = "https://proxy.xhamster.biz.id/proxyList.txt";
const UUIDS = `aaaaaaa1-bbbb-4ccc-accc-eeeeeeeeeee1`;
const TELEGRAM_BOT_TOKEN = '7826108422:AAEmQiVx2TvdAZnvpKw2zJZUvv8fOEGruW0';
const TELEGRAM_API_URL = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}`;
const APICF = 'https://ipcf.rmtq.fun/json/';
const FAKE_HOSTNAME = 'tunneling.bmkg.xyz';
const ownerId = 7114686701; // Ganti dengan chat_id pemilik bot (angka tanpa tanda kutip)




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

// Fungsi untuk menangani `/delete` (menghapus webhook)
async function handleDelete(request) {
  const response = await fetch(`${TELEGRAM_API_URL}/deleteWebhook`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  });

  if (response.ok) {
    return new Response('Webhook deleted successfully', { status: 200 });
  }
  return new Response('Failed to delete webhook', { status: 500 });
}

// Fungsi untuk menangani `/info` (mendapatkan info webhook)
async function handleInfo(request) {
  const response = await fetch(`${TELEGRAM_API_URL}/getWebhookInfo`);

  if (response.ok) {
    const data = await response.json();
    return new Response(JSON.stringify(data), { status: 200 });
  }
  return new Response('Failed to retrieve webhook info', { status: 500 });
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

// Fungsi untuk menangani `/sendMessage`
async function handleSendMessage(request) {
  const { chat_id, text } = await request.json();
  const response = await fetch(`${TELEGRAM_API_URL}/sendMessage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chat_id, text }),
  });

  if (response.ok) {
    return new Response('Message sent successfully', { status: 200 });
  }
  return new Response('Failed to send message', { status: 500 });
}

// Fungsi untuk menangani `/getUpdates`
async function handleGetUpdates(request) {
  const response = await fetch(`${TELEGRAM_API_URL}/getUpdates`);

  if (response.ok) {
    const data = await response.json();
    return new Response(JSON.stringify(data), { status: 200 });
  }
  return new Response('Failed to get updates', { status: 500 });
}

// Fungsi untuk menangani `/deletePending` - menarik pembaruan yang tertunda
async function handleDeletePending(request) {
  // Hapus webhook untuk menghindari pembaruan tertunda
  const deleteResponse = await fetch(`${TELEGRAM_API_URL}/deleteWebhook`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  });

  if (deleteResponse.ok) {
    // Setelah menghapus webhook, atur webhook kembali
    const host = request.headers.get('Host');
    const webhookUrl = `https://${host}/webhook`;

    const setResponse = await fetch(`${TELEGRAM_API_URL}/setWebhook`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: webhookUrl }),
    });

    if (setResponse.ok) {
      return new Response('Pending updates deleted by resetting webhook', { status: 200 });
    }
    return new Response('Failed to set webhook after deletion', { status: 500 });
  }

  return new Response('Failed to delete webhook', { status: 500 });
}

async function handleDropPending(request) {
  const response = await fetch(`${TELEGRAM_API_URL}/getUpdates`);

  if (response.ok) {
    const data = await response.json();

    if (data.result && data.result.length > 0) {
      // Hanya mengambil pembaruan dan tidak memprosesnya
      return new Response('Dropped pending updates successfully', { status: 200 });
    }
    return new Response('No pending updates found', { status: 200 });
  }

  return new Response('Failed to get pending updates', { status: 500 });
}


// Routing utama sebelum mencapai handler default
async function routeRequest(request) {
  const url = new URL(request.url);

  if (url.pathname === '/active') {
    return await handleActive(request);
  }

  if (url.pathname === '/delete') {
    return await handleDelete(request);
  }

  if (url.pathname === '/info') {
    return await handleInfo(request);
  }

  if (url.pathname === '/webhook' && request.method === 'POST') {
    return await handleWebhook(request);
  }

  if (url.pathname === '/sendMessage') {
    return await handleSendMessage(request);
  }

  if (url.pathname === '/getUpdates') {
    return await handleGetUpdates(request);
  }

  if (url.pathname === '/deletePending') {
    return await handleDeletePending(request);
  }

  if (url.pathname === '/dropPending') {
    return await handleDropPending(request);
  }

  return null;
}


async function checkIPAndPort(ip, port) {
  const apiUrl = `${apiCheck}${ip}:${port}`;
  try {
    const apiResponse = await fetch(apiUrl);
    const apiData = await apiResponse.json();
    const result = {
      ip: ip,
      port: port,
      status: apiData.STATUS || null
    };
    return new Response(JSON.stringify(result, null, 2), {
      status: 200,
      headers: { "Content-Type": "application/json;charset=utf-8" }
    });
  } catch (err) {
    return new Response(`An error occurred while fetching API: ${err.toString()}`, {
      status: 500,
    });
  }
}

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
        const proxyMatch = url.pathname.match(/^\/Free-CF-Proxy-(.+[:=-]\d+)$/);

        if (proxyMatch) {
          proxyIP = proxyMatch[1];
          return await websockerHandler(request);
        }
      }

      // Memeriksa URL path untuk IP dan Port
      if (url.pathname.startsWith("/")) {
        const pathParts = url.pathname.slice(1).split(":");
        if (pathParts.length === 2) {
          const [ip, port] = pathParts;
          return await checkIPAndPort(ip, port);
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

async function handleCallbackQuery(callbackQuery) {
  const callbackData = callbackQuery.data;
  const chatId = callbackQuery.message.chat.id;

  const wildkere = FAKE_HOSTNAME; // Ganti dengan host default yang benar

  try {
    if (callbackData.startsWith('create_bmkg')) {
      const [_, ip, port, isp] = callbackData.split('|');
      await handleBmkgCreation(chatId, ip, port, isp);
    } else if (callbackData.startsWith('create_ndeso')) {
      const [_, ip, port, isp] = callbackData.split('|');
      await handleNdesoCreation(chatId, ip, port, isp);
    } else if (callbackData.startsWith('create_ndeso1')) {
      const [_, ip, port, isp] = callbackData.split('|');
      await handleNdeso1Creation(chatId, ip, port, isp);
    } else if (callbackData.startsWith('create_turah')) {
      const [_, ip, port, isp] = callbackData.split('|');
      await handleTurahCreation(chatId, ip, port, isp);
    } else if (callbackData.startsWith('create_najah')) {
      const [_, ip, port, isp] = callbackData.split('|');
      await handleNajahCreation(chatId, ip, port, isp);
    } else if (callbackData.startsWith('create_coudproxy')) {
      const [_, ip, port, isp] = callbackData.split('|');
      await handleCoudproxyCreation(chatId, ip, port, isp);
    } else if (callbackData.startsWith('create_xhamster')) {
      const [_, ip, port, isp] = callbackData.split('|');
      await handleXhamsterCreation(chatId, ip, port, isp);
    } else if (callbackData.startsWith('create_cepu')) {
      const [_, ip, port, isp] = callbackData.split('|');
      await handleCepuCreation(chatId, ip, port, isp);
    } else if (callbackData.startsWith('create_kere')) {
      const [_, ip, port, isp] = callbackData.split('|');
      await handleKereCreation(chatId, ip, port, isp);
    } else if (callbackData.startsWith('create_xnxxx')) {
      const [_, ip, port, isp] = callbackData.split('|');
      await handleXnxxxCreation(chatId, ip, port, isp);
    } 

    // Konfirmasi callback query ke Telegram
    await fetch(`${TELEGRAM_API_URL}/answerCallbackQuery`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        callback_query_id: callbackQuery.id,
      }),
    });
  } catch (error) {
    console.error('Error handling callback query:', error);
  }

  return new Response('OK', { status: 200 });
}


let userChatIds = [];

// Function to handle incoming messages
async function handleMessage(message) {
  const text = message.text;
  const chatId = message.chat.id;

  // Menangani perintah /start
  if (text === '/start') {
    await handleStartCommand(chatId);

    // Menambahkan pengguna ke daftar jika belum ada
    if (!userChatIds.includes(chatId)) {
      userChatIds.push(chatId);
    }

  // Menangani perintah /info
  } else if (text === '/info') {
    await handleGetInfo(chatId);

    // Menangani perintah /getcountry
  } else if (text === '/getcountry') {
    await handleGetgetcountry(chatId);

    // Menangani perintah /subapi
  } else if (text === '/subapi') {
    await handleGetsubapi(chatId);

  // Menangani perintah /listwildcard
  } else if (text === '/listwildcard') {
    await handleListWildcard(chatId);
    
      // Menangani perintah /listdomain
  } else if (text === '/listdomain') {
    await handleListDomain(chatId);
  
  // Menangani perintah /listpremium
  } else if (text === '/listpremium') {
    await handleListPremium(chatId);
    
  // Menangani perintah /getrandomip
  } else if (text === '/getrandomip') {
    await handleGetRandomIPCommand(chatId);

  // Menangani perintah /getrandom <CountryCode>
  } else if (text.startsWith('/getrandom')) {
    const countryId = text.slice(10); // Mengambil kode negara setelah "/getrandom" tanpa spasi
    if (countryId) {
        await handleGetRandomCountryCommand(chatId, countryId);
    } else {
        await sendTelegramMessage(chatId, '⚠️ Harap tentukan kode negara setelah `/getrandom` (contoh: `/getrandomID`, `/getrandomUS`).');
    }


  // Menangani perintah /broadcast
  } else if (text.startsWith('/broadcast')) {
    await handleBroadcastCommand(message);

  // Menangani format IP:Port
  } else if (isValidIPPortFormat(text)) {
    await handleIPPortCheck(text, chatId);

  // Pesan tidak dikenali atau format salah
  } else {
    await sendTelegramMessage(chatId, '⚠️ Format tidak valid. Gunakan format IP:Port yang benar (contoh: 192.168.1.1:80).');
  }

  return new Response('OK', { status: 200 });
}

// Fungsi untuk menangani perintah /broadcast
async function handleBroadcastCommand(message) {
  const chatId = message.chat.id;
  const text = message.text;

  // Memeriksa apakah pengirim adalah pemilik bot
  if (chatId !== ownerId) {
    await sendTelegramMessage(chatId, '⚠️ Anda bukan pemilik bot ini.');
    return;
  }

  // Mengambil pesan setelah perintah /broadcast
  const broadcastMessage = text.replace('/broadcast', '').trim();
  if (!broadcastMessage) {
    await sendTelegramMessage(chatId, '⚠️ Harap masukkan pesan setelah perintah /broadcast.');
    return;
  }

  // Mengirim pesan ke semua pengguna yang terdaftar
  if (userChatIds.length === 0) {
    await sendTelegramMessage(chatId, '⚠️ Tidak ada pengguna untuk menerima pesan broadcast.');
    return;
  }

  for (const userChatId of userChatIds) {
    try {
      await sendTelegramMessage(userChatId, broadcastMessage);
    } catch (error) {
      console.error(`Error mengirim pesan ke ${userChatId}:`, error);
    }
  }

  await sendTelegramMessage(chatId, `✅ Pesan telah disebarkan ke ${userChatIds.length} pengguna.`);
}

// Fungsi untuk mengirim pesan ke pengguna melalui Telegram API
async function sendTelegramMessage(chatId, message) {
  const url = `${TELEGRAM_API_URL}/sendMessage`;

  const payload = {
    chat_id: chatId,
    text: message,
    parse_mode: 'Markdown', // Untuk memformat teks
  };

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    });

    const result = await response.json();
    if (!result.ok) {
      console.error('Gagal mengirim pesan:', result);
    }
  } catch (error) {
    console.error('Error saat mengirim pesan:', error);
  }
}

// Function to handle the /start command
async function handleStartCommand(chatId) {
  const welcomeMessage = `
🎉 Selamat datang di Free Vpn Bot! 🎉

💡 Cara Penggunaan:
1️⃣ Kirimkan Proxy IP:Port dalam format yang benar.
       Contoh: \`192.168.1.1:8080\`
2️⃣ Bot akan mengecek status Proxy untuk Anda.

✨ Anda bisa memilih opsi untuk membuat VPN Tunnel CloudFlare Gratis Menggunakan ProxyIP yang sudah di Cek dengan format:
- 🌐 VLESS
- 🔐 TROJAN
- 🛡️ Shadowsocks

🚀 Mulai sekarang dengan mengirimkan Proxy IP:Port Anda!

📌 Daftar Commands : 

/info
/getrandomip
/getcountry
/listwildcard
/listdomain
/listpremium
/subapi


👨‍💻 Dikembangkan oleh: [Mode](https://t.me/kstore877)

🌐 WEB VPN TUNNEL : [VPN Tunnel CloudFlare](https://tunneling.bmkg.xyz)
📺 CHANNEL : [Channel](https://t.me/kstore877)
👥 GROUP TELE : [Grup](https://t.me/+Rs4HvJtagXZlYTNl)
👥 GROUP WA : [Grup WA](https://chat.whatsapp.com/L9bbkRbzyozEFJHgGc9pPh)

ORDER PREMIUM CONTACT ADMIN
🧔 ADMIN TELE : [ADMIN TELE](https://t.me/kcepu877)
🧔 ADMIN WA : [ADMIN WA](https://wa.me/6281335135082)

  `;
  await sendTelegramMessage(chatId, welcomeMessage);
}

async function handleGetInfo(chatId) {
  const InfoMessage = `
🎉 Commands di Free Vpn Bot! 🎉

🟢 \`/getrandomip\`
🟢 \`/getcountry\`
🟢 \`/listwildcard\`
🟢 \`/listdomain\`
🟢 \`/listpremium\`
🟢 \`/subapi\`

👨‍💻 Dikembangkan oleh: [Mode](https://t.me/kstore877)

🌐 WEB VPN TUNNEL : [VPN Tunnel CloudFlare](https://tunneling.bmkg.xyz)
📺 CHANNEL : [Channel](https://t.me/kstore877
👥 GROUP TELE : [Grup](https://t.me/+Rs4HvJtagXZlYTNl)
👥 GROUP WA : [Grup WA](https://chat.whatsapp.com/L9bbkRbzyozEFJHgGc9pPh)

ORDER PREMIUM CONTACT ADMIN
🧔 ADMIN TELE : [ADMIN TELE](https://t.me/kcepu877)
🧔 ADMIN WA : [ADMIN WA](https://wa.me/6281335135082)
  `;
  await sendTelegramMessage(chatId, InfoMessage);
}

async function handleGetsubapi(chatId) {
  const InfoMessage = `
🎉 Commands di Free Vpn Bot! 🎉


URL = https://tunneling.bmkg.xyz/api
aplikasi = v2ray, v2rayng, clash, nekobox, singbox, surfboard, husi,
Acount = ?type=vless, trojan, ss,
Bug = &bug=\`quiz.int.vidio.com\`, 
    \`ava.game.naver.com\`,
    \`business.blibli.com\`,
    \`graph.instagram.com\`,
    \`quiz.int.vidio.com\`,
    \`live.iflix.com\`,
    \`support.zoom.us\`,
    \`blog.webex.com\`,
    \`investors.spotify.com\`,
    \`cache.netflix.com\`,
    \`zaintest.vuclip.com\`,
    \`ads.ruangguru.com\`,
    \`api.midtrans.com\`,
    \`investor.fb.com\`,
tls/ntls = &tls=true, false,
wildcard = &wildcard=true, false
limit = &limit=10
Country = &country=RANDOM, all, SG, ID, US, DLL


https://tunneling.bmkg.xyz/api/v2ray?type=vless&bug=quiz.int.vidio.com&tls=true&wildcard=true&limit=10&country=SG

👨‍💻 Dikembangkan oleh: [Mode](https://t.me/kstore877)

🌐 WEB VPN TUNNEL : [VPN Tunnel CloudFlare](https://tunneling.bmkg.xyz)
📺 CHANNEL : [Channel](https://t.me/kstore877
👥 GROUP TELE : [Grup](https://t.me/+Rs4HvJtagXZlYTNl)
👥 GROUP WA : [Grup WA](https://chat.whatsapp.com/L9bbkRbzyozEFJHgGc9pPh)

ORDER PREMIUM CONTACT ADMIN
🧔 ADMIN TELE : [ADMIN TELE](https://t.me/kcepu877)
🧔 ADMIN WA : [ADMIN WA](https://wa.me/6281335135082)
  `;
  await sendTelegramMessage(chatId, InfoMessage);
}


// Fungsi untuk mengirimkan negara acak
async function handleGetRandom(chatId, countryCode) {
  try {
    // Daftar negara dan informasi terkaitnya
    const countries = {
      AE: 'Uni Emirat Arab',
      AF: 'Afganistan',
      AL: 'Albania',
      DZ: 'Aljazair',
      // Anda bisa menambah lebih banyak negara sesuai kebutuhan
    };

    const countryName = countries[countryCode];
    const randomInfo = `Berikut adalah info acak untuk negara ${countryName} 🇦🇪`;

    // Mengirim pesan dengan informasi acak negara
    const response = await fetch(`${TELEGRAM_API_URL}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: chatId,
        text: randomInfo,
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('Failed to send random country message:', errorText);
    } else {
      console.log(`Sent random info for ${countryName}.`);
    }
  } catch (error) {
    console.error('Error sending random country info:', error);
  }
}

// Callback untuk menangani request getrandom
async function handleCallbackQuery(callbackQuery) {
  const chatId = callbackQuery.message.chat.id;
  const data = callbackQuery.data;

  // Menangani command /getrandom dan mengidentifikasi kode negara
  if (data.startsWith('/getrandom')) {
    const countryCode = data.split('getrandom')[1];  // Mendapatkan kode negara dari data callback
    await handleGetRandom(chatId, countryCode);  // Panggil fungsi handleGetRandom
  }
}

// Menangani callback query Telegram
async function handleUpdate(update) {
  if (update.callback_query) {
    await handleCallbackQuery(update.callback_query);
  }
}



async function handleListWildcard(chatId) {
  const wildkere = `tunneling.bmkg.xyz`;
  const infoMessage = `
🎉 List Wildcard VPN Tunnel Free Vpn Bot! 


🟢 \`ava.game.naver.com.${wildkere}\`
🟢 \`business.blibli.com.${wildkere}\`
🟢 \`graph.instagram.com.${wildkere}\`
🟢 \`quiz.int.vidio.com.${wildkere}\`
🟢 \`live.iflix.com.${wildkere}\`
🟢 \`support.zoom.us.${wildkere}\`
🟢 \`blog.webex.com.${wildkere}\`
🟢 \`investors.spotify.com.${wildkere}\`
🟢 \`cache.netflix.com.${wildkere}\`
🟢 \`zaintest.vuclip.com.${wildkere}\`
🟢 \`ads.ruangguru.com.${wildkere}\`
🟢 \`api.midtrans.com.${wildkere}\`


👨‍💻 Dikembangkan oleh: [Mode](https://t.me/kstore877)

🌐 WEB VPN TUNNEL : [VPN Tunnel CloudFlare](https://tunneling.bmkg.xyz)
📺 CHANNEL : [Channel](https://t.me/kstore877)
👥 GROUP TELE : [Grup Tele](https://t.me/+Rs4HvJtagXZlYTNl)
👥 GROUP WA : [Grup WA](https://chat.whatsapp.com/L9bbkRbzyozEFJHgGc9pPh)

ORDER PREMIUM CONTACT ADMIN
🧔 ADMIN TELE : [ADMIN TELE](https://t.me/kcepu877)
🧔 ADMIN WA : [ADMIN WA](https://wa.me/6281335135082)


  `;
  await sendTelegramMessage(chatId, infoMessage);
}


async function handleListDomain(chatId) {
  const wildkere = `tunneling.bmkg.xyz`;
  const infoMessage = `
🎉 List Domain VPN Tunnel Free Vpn Bot! 


✅ \`free-cf.xhamster.biz.id\` ✅
✅ \`free-cf.turah.my.id\` ✅
✅ \`free-cf.ndeso.xyz\` ✅
✅ \`free-cf.ndeso.web.id\` ✅
✅ \`free-cf.kere.us.kg\` ✅
✅ \`free-cf.cepu.us.kg\` ✅
✅ \`free-cf.najah.biz.id.\` ✅
✅ \`web.bmkg.xyz\` ✅
✅ \`loss.cloudproxyip.my.id\` ✅



👨‍💻 Dikembangkan oleh: [Mode](https://t.me/kstore877)

🌐 WEB VPN TUNNEL : [VPN Tunnel CloudFlare](https://tunneling.bmkg.xyz)
📺 CHANNEL : [Channel](https://t.me/kstore877)
👥 GROUP TELE : [Grup Tele](https://t.me/+Rs4HvJtagXZlYTNl)
👥 GROUP WA : [Grup WA](https://chat.whatsapp.com/L9bbkRbzyozEFJHgGc9pPh)

ORDER PREMIUM CONTACT ADMIN
🧔 ADMIN TELE : [ADMIN TELE](https://t.me/kcepu877)
🧔 ADMIN WA : [ADMIN WA](https://wa.me/6281335135082)


  `;
  await sendTelegramMessage(chatId, infoMessage);
}


async function handleListPremium(chatId) {
  const infoMessage = `
🎉 *List PREMIUM VPN Tunnel Bot!* 🎉

READY SERVER PREMIUM SSH, VLESS, VMESS & TROJAN. SUPPORT VC, GAME DLL
[MASA AKTIF 30 HARI & FULL GARANSI]


📌 *Daftar Server:*

\`\`\`
server--🇮🇩ID-BIZNET PRO1 2DEV
"12K"
"VMESS & TROJAN"
\`\`\`
\`\`\`
server--🇮🇩ID-BIZNET 2
"10K"
"VMESS & TROJAN"
\`\`\`
\`\`\`
server--🇮🇩ID-UNINET STB1
"12K"
"TROJAN"
\`\`\`
\`\`\`
server--🇮🇩ID1-RTRWNET VOCUHERAN
"65K"
"VMESS"
\`\`\`
\`\`\`
server--🇮🇩WIJAYA1
"10K"
"VMESS & VLESS"
\`\`\`
\`\`\`
server--🇮🇩ID-DEWAWEB2
"10K"
"VMESS & TROJAN"
\`\`\`
\`\`\`
server--🇮🇩ID-AMS1
"10K"
"VMESS & VLESS"
\`\`\`
\`\`\`
server--🇸🇬SGGS-2 STB
"12K"
"TROJAN"
\`\`\`
\`\`\`
server--🇸🇬SGGS-1 STB
"12K"
"VMESS"
\`\`\`
\`\`\`
server--🇸🇬DO1-NON STB
"8K"
"TROJAN"
\`\`\`
\`\`\`
server--🇸🇬SG1-RTRWNET SINGAPORE
"45K"
"VMESS"
\`\`\`
\`\`\`
server--🇸🇬DO3-SSH
"8K"
"SSH"
\`\`\`
\`\`\`
server--🇸🇬SG1-LINODE
"10K"
"SSH, VMESS & TROJAN"
\`\`\`
\`\`\`
server--🇸🇬DO2-NON STB
"8K"
"VMESS & VLESS"
\`\`\`
\`\`\`
server--🇸🇬SGDO-2DEV
"10K"
"SSH, VLESS, VMESS & TROJAN"
\`\`\`
\`\`\`
server--🇸🇬DO-4 NON STB
"8K"
"VMESS & VLESS"
\`\`\`
\`\`\`
server--🇸🇬SG-PREM1
"10K"
"VMESS"
\`\`\`
\`\`\`
server--🇮🇩ID-SANTOSA1 50Mbps
"8K"
"VMESS & TROJAN"
\`\`\`
\`\`\`
server--🇮🇩ID-NUSA MAX
"12K"
"SSH & VMESS"
\`\`\`

----------------------------------------

👨‍💻 *Admin & Kontak:*  
🛠 *ADMIN 1:* @kcepu877  
🛠 *ADMIN 2:* @epoenk877  

🔗 *Website FREE VPN Tunnel:* [FREE VPN Tunnel CloudFlare](https://tunneling.bmkg.xyz)  
📢 *Channel Telegram:* [Klik di sini](https://t.me/kstore877)  
👥 *Grup Telegram:* [Klik di sini](https://t.me/+Rs4HvJtagXZlYTNl)  
👥 *Grup WhatsApp:* [Klik di sini](https://chat.whatsapp.com/L9bbkRbzyozEFJHgGc9pPh)  

📩 *Order Premium:*  
📱 *Admin Telegram:* [Klik di sini](https://t.me/kcepu877)  
📱 *Admin WhatsApp:* [Klik di sini](https://wa.me/6281335135082)  

----------------------------------------
  `;
  await sendTelegramMessage(chatId, infoMessage);
}





// Function to handle the /getrandomip command
async function handleGetRandomIPCommand(chatId) {
  try {
    // Fetching the Proxy IP list from the GitHub raw URL
    const response = await fetch('https://proxy.xhamster.biz.id/proxyList.txt');
    const data = await response.text();

    // Split the data into an array of Proxy IPs
    const proxyList = data.split('\n').filter(line => line.trim() !== '');

    // Randomly select 10 Proxy IPs
    const randomIPs = [];
    for (let i = 0; i < 10 && proxyList.length > 0; i++) {
      const randomIndex = Math.floor(Math.random() * proxyList.length);
      randomIPs.push(proxyList[randomIndex]);
      proxyList.splice(randomIndex, 1); // Remove the selected item from the list
    }

    // Format the random IPs into a message
    const message = `🔑 **Here are 10 random Proxy IPs:**\n\n` +
      randomIPs.map(ip => {
        const [ipAddress, port, country, provider] = ip.split(',');
        // Replace dots with spaces in the provider name
        const formattedProvider = provider.replace(/\./g, ' ');
        return `🌍 **\`${ipAddress}:${port}\`**\n📍 **Country:** ${country}\n💻 **Provider:** ${formattedProvider}\n`;
      }).join('\n');

    await sendTelegramMessage(chatId, message);
  } catch (error) {
    console.error('Error fetching proxy list:', error);
    await sendTelegramMessage(chatId, '⚠️ There was an error fetching the Proxy list. Please try again later.');
  }
}

// Function to handle the /getrandom <Country> command
async function handleGetRandomCountryCommand(chatId, countryId) {
  try {
    const response = await fetch('https://proxy.xhamster.biz.id/proxyList.txt');
    const data = await response.text();
    const proxyList = data.split('\n').filter(line => line.trim() !== '');
    const filteredProxies = proxyList.filter(ip => {
      const [ipAddress, port, country, provider] = ip.split(',');
      return country.toUpperCase() === countryId.toUpperCase(); // Country case-insensitive comparison
    });
    const randomIPs = [];
    for (let i = 0; i < 10 && filteredProxies.length > 0; i++) {
      const randomIndex = Math.floor(Math.random() * filteredProxies.length);
      randomIPs.push(filteredProxies[randomIndex]);
      filteredProxies.splice(randomIndex, 1); // Remove the selected item from the list
    }
    if (randomIPs.length === 0) {
      await sendTelegramMessage(chatId, `⚠️ No proxies found for country code **${countryId}**.`);
      return;
    }
    const message = `🔑 **Here are 10 random Proxy IPs for country ${countryId}:**\n\n` +
      randomIPs.map(ip => {
        const [ipAddress, port, country, provider] = ip.split(',');
        // Replace dots with spaces in the provider name
        const formattedProvider = provider.replace(/\./g, ' ');
        return `🌍 **\`${ipAddress}:${port}\`**\n📍 **Country:** ${country}\n💻 **Provider:** ${formattedProvider}\n`;
      }).join('\n');

    await sendTelegramMessage(chatId, message);
  } catch (error) {
    console.error('Error fetching proxy list:', error);
    await sendTelegramMessage(chatId, '⚠️ There was an error fetching the Proxy list. Please try again later.');
  }
}
  
async function handleIPPortCheck(ipPortText, chatId) {
  const [ip, port] = ipPortText.split(':');
  const result = await checkIPPort(ip, port, chatId);
  if (result) await sendTelegramMessage(chatId, result);
}

function isValidIPPortFormat(input) {
  const regex = /^(\d{1,3}\.){3}\d{1,3}:\d{1,5}$/;
  return regex.test(input);
}

async function checkIPPort(ip, port, chatId) {
  try {
    // Kirim pesan sementara bahwa IP sedang diperiksa
    await sendTelegramMessage(chatId, `🔍 *Cheking ProxyIP ${ip}:${port}...*`);
    const response = await fetch(`${APICF}?ip=${ip}:${port}`);
    if (!response.ok) throw new Error(`API Error: ${response.statusText}`);
    const data = await response.json();
    const filterISP = (isp) => {
      // Hapus karakter selain huruf, angka, spasi, dan tanda kurung ( )
      const sanitizedISP = isp.replace(/[^a-zA-Z0-9\s()]/g, "");
      const words = sanitizedISP.split(" ");
      if (words.length <= 3) return sanitizedISP; // Jika ISP memiliki <= 3 kata, kembalikan apa adanya
      return `${words.slice(0, 2).join(" ")} ${words[words.length - 1]}`;
    };
    const filteredISP = filterISP(data.ISP);

    // Tentukan status aktif/tidak
    const status = data.STATUS === "✔ AKTIF ✔" ? "✅ Aktif" : "❌ Tidak Aktif";

    // Buat pesan hasil cek
    const resultMessage = `
🌐 Hasil Cek IP dan Port:
━━━━━━━━━━━━━━━━━━━━━━━
📍 IP: ${data.IP}
🔌 Port: ${data.PORT}
📡 ISP: ${filteredISP}
🏢 ASN: ${data.ASN}
🌆 Kota: ${data.KOTA}
📶 Status: ${status}
━━━━━━━━━━━━━━━━━━━━━━━
 
    `;

    // Kirim hasil cek
    await sendTelegramMessage(chatId, resultMessage);

    // Kirim keyboard interaktif
    await sendInlineKeyboard(chatId, data.IP, data.PORT, filteredISP);

  } catch (error) {
    // Tampilkan pesan error
    await sendTelegramMessage(chatId, `⚠️ Terjadi kesalahan saat memeriksa IP dan port: ${error.message}`);
  }
}



async function handleBmkgCreation(chatId, ip, port, isp) {
  
  const UUIDS = "aaaaaaa1-bbbb-4ccc-accc-eeeeeeeeeee1";  // Perbaiki UUID tanpa backtick yang berlebihan
  const path = `/Free-CF-Proxy-${ip}-${port}`;

  // Konfigurasi Link VPN
  const ssTls = `ss://${btoa(`none:${UUIDS}`)}@tunneling.bmkg.xyz:443?encryption=none&type=ws&host=tunneling.bmkg.xyz&path=${encodeURIComponent(path)}&security=tls&sni=tunneling.bmkg.xyz#${isp}`;
  const ssNTls = `ss://${btoa(`none:${UUIDS}`)}@tunneling.bmkg.xyz:80?encryption=none&type=ws&host=tunneling.bmkg.xyz&path=${encodeURIComponent(path)}&security=none&sni=tunneling.bmkg.xyz#${isp}`;
  const vlessTLS = `vless://${UUIDS}@tunneling.bmkg.xyz:443?path=${encodeURIComponent(path)}&security=tls&host=tunneling.bmkg.xyz&type=ws&sni=tunneling.bmkg.xyz#${isp}`;
  const vlessNTLS = `vless://${UUIDS}@tunneling.bmkg.xyz:80?path=${encodeURIComponent(path)}&security=none&host=tunneling.bmkg.xyz&type=ws&sni=tunneling.bmkg.xyz#${isp}`;
  const trojanTLS = `trojan://${UUIDS}@tunneling.bmkg.xyz:443?path=${encodeURIComponent(path)}&security=tls&host=tunneling.bmkg.xyz&type=ws&sni=tunneling.bmkg.xyz#${isp}`;
  const trojanNTLS = `trojan://${UUIDS}@tunneling.bmkg.xyz:80?path=${encodeURIComponent(path)}&security=none&host=tunneling.bmkg.xyz&type=ws&sni=tunneling.bmkg.xyz#${isp}`;

  
      const message = `
Success Create Vpn Server 
🌍 \`${isp}\` \n⚜️ \`${ip}:${port}\` ⚜️
⚜️ **VPN Configurations** ⚜️

━━━━━━━━━━━━━━━━━━━━━━━
🔗 **VLESS** 
━━━━━━━━━━━━━━━━━━━━━━━
✅ **TLS** : 
\`\`\`
${vlessTLS}
\`\`\`
✅ **Non-TLS** : 
\`\`\`
${vlessNTLS}
\`\`\`


━━━━━━━━━━━━━━━━━━━━━━━
🔗 **Trojan** 
━━━━━━━━━━━━━━━━━━━━━━━
✅ **TLS** : 
\`\`\`
${trojanTLS}
\`\`\`
✅ **Non-TLS** : 
\`\`\`
${trojanNTLS}
\`\`\`


━━━━━━━━━━━━━━━━━━━━━━━
🔗 **ShadowSocks** 
━━━━━━━━━━━━━━━━━━━━━━━
✅ **TLS** : 
\`\`\`
${ssTls}
\`\`\`
✅ **Non-TLS** : 
\`\`\`
${ssNTls}
\`\`\`



━━━━━━━━━━━━━━━━━━━━━━━
[WEB FREE VPN](https://tunneling.bmkg.xyz)
🚀 **ORDER PREMIUM CONTACT ADMIN**  
[ADMIN TELE](https://t.me/kcepu877)  
[ADMIN WA](https://wa.me/6281335135082)  

`;

  await sendTelegramMessage(chatId, message);
}
 
async function handleNdesoCreation(chatId, ip, port, isp) {
  
  const UUIDS = "aaaaaaa1-bbbb-4ccc-accc-eeeeeeeeeee1";  // Perbaiki UUID tanpa backtick yang berlebihan
  const path = `/Free-CF-Proxy-${ip}-${port}`;

  // Konfigurasi Link VPN
  const ssTls = `ss://${btoa(`none:${UUIDS}`)}@tunneling.ndeso.xyz:443?encryption=none&type=ws&host=tunneling.ndeso.xyz&path=${encodeURIComponent(path)}&security=tls&sni=tunneling.ndeso.xyz#${isp}`;
  const ssNTls = `ss://${btoa(`none:${UUIDS}`)}@tunneling.ndeso.xyz:80?encryption=none&type=ws&host=tunneling.ndeso.xyz&path=${encodeURIComponent(path)}&security=none&sni=tunneling.ndeso.xyz#${isp}`;
  const vlessTLS = `vless://${UUIDS}@tunneling.ndeso.xyz:443?path=${encodeURIComponent(path)}&security=tls&host=tunneling.ndeso.xyz&type=ws&sni=tunneling.ndeso.xyz#${isp}`;
  const vlessNTLS = `vless://${UUIDS}@tunneling.ndeso.xyz:80?path=${encodeURIComponent(path)}&security=none&host=tunneling.ndeso.xyz&type=ws&sni=tunneling.ndeso.xyz#${isp}`;
  const trojanTLS = `trojan://${UUIDS}@tunneling.ndeso.xyz:443?path=${encodeURIComponent(path)}&security=tls&host=tunneling.ndeso.xyz&type=ws&sni=tunneling.ndeso.xyz#${isp}`;
  const trojanNTLS = `trojan://${UUIDS}@tunneling.ndeso.xyz:80?path=${encodeURIComponent(path)}&security=none&host=tunneling.ndeso.xyz&type=ws&sni=tunneling.ndeso.xyz#${isp}`;

  
      const message = `
Success Create Vpn Server 
🌍 \`${isp}\` \n⚜️ \`${ip}:${port}\` ⚜️
⚜️ **VPN Configurations** ⚜️

━━━━━━━━━━━━━━━━━━━━━━━
🔗 **VLESS** 
━━━━━━━━━━━━━━━━━━━━━━━
✅ **TLS** : 
\`\`\`
${vlessTLS}
\`\`\`
✅ **Non-TLS** : 
\`\`\`
${vlessNTLS}
\`\`\`


━━━━━━━━━━━━━━━━━━━━━━━
🔗 **Trojan** 
━━━━━━━━━━━━━━━━━━━━━━━
✅ **TLS** : 
\`\`\`
${trojanTLS}
\`\`\`
✅ **Non-TLS** : 
\`\`\`
${trojanNTLS}
\`\`\`


━━━━━━━━━━━━━━━━━━━━━━━
🔗 **ShadowSocks** 
━━━━━━━━━━━━━━━━━━━━━━━
✅ **TLS** : 
\`\`\`
${ssTls}
\`\`\`
✅ **Non-TLS** : 
\`\`\`
${ssNTls}
\`\`\`



━━━━━━━━━━━━━━━━━━━━━━━
[WEB FREE VPN](https://tunneling.bmkg.xyz)
🚀 **ORDER PREMIUM CONTACT ADMIN**  
[ADMIN TELE](https://t.me/kcepu877)  
[ADMIN WA](https://wa.me/6281335135082)  

`;

  await sendTelegramMessage(chatId, message);
}
 
async function handleNdeso1Creation(chatId, ip, port, isp) {
  
  const UUIDS = "aaaaaaa1-bbbb-4ccc-accc-eeeeeeeeeee1";  // Perbaiki UUID tanpa backtick yang berlebihan
  const path = `/Free-CF-Proxy-${ip}-${port}`;

  // Konfigurasi Link VPN
  const ssTls = `ss://${btoa(`none:${UUIDS}`)}@tunneling.ndeso.web.id:443?encryption=none&type=ws&host=tunneling.ndeso.web.id&path=${encodeURIComponent(path)}&security=tls&sni=tunneling.ndeso.web.id#${isp}`;
  const ssNTls = `ss://${btoa(`none:${UUIDS}`)}@tunneling.ndeso.web.id:80?encryption=none&type=ws&host=tunneling.ndeso.web.id&path=${encodeURIComponent(path)}&security=none&sni=tunneling.ndeso.web.id#${isp}`;
  const vlessTLS = `vless://${UUIDS}@tunneling.ndeso.web.id:443?path=${encodeURIComponent(path)}&security=tls&host=tunneling.ndeso.web.id&type=ws&sni=tunneling.ndeso.web.id#${isp}`;
  const vlessNTLS = `vless://${UUIDS}@tunneling.ndeso.web.id:80?path=${encodeURIComponent(path)}&security=none&host=tunneling.ndeso.web.id&type=ws&sni=tunneling.ndeso.web.id#${isp}`;
  const trojanTLS = `trojan://${UUIDS}@tunneling.ndeso.web.id:443?path=${encodeURIComponent(path)}&security=tls&host=tunneling.ndeso.web.id&type=ws&sni=tunneling.ndeso.web.id#${isp}`;
  const trojanNTLS = `trojan://${UUIDS}@tunneling.ndeso.web.id:80?path=${encodeURIComponent(path)}&security=none&host=tunneling.ndeso.web.id&type=ws&sni=tunneling.ndeso.web.id#${isp}`;

  
      const message = `
Success Create Vpn Server 
🌍 \`${isp}\` \n⚜️ \`${ip}:${port}\` ⚜️
⚜️ **VPN Configurations** ⚜️

━━━━━━━━━━━━━━━━━━━━━━━
🔗 **VLESS** 
━━━━━━━━━━━━━━━━━━━━━━━
✅ **TLS** : 
\`\`\`
${vlessTLS}
\`\`\`
✅ **Non-TLS** : 
\`\`\`
${vlessNTLS}
\`\`\`


━━━━━━━━━━━━━━━━━━━━━━━
🔗 **Trojan** 
━━━━━━━━━━━━━━━━━━━━━━━
✅ **TLS** : 
\`\`\`
${trojanTLS}
\`\`\`
✅ **Non-TLS** : 
\`\`\`
${trojanNTLS}
\`\`\`


━━━━━━━━━━━━━━━━━━━━━━━
🔗 **ShadowSocks** 
━━━━━━━━━━━━━━━━━━━━━━━
✅ **TLS** : 
\`\`\`
${ssTls}
\`\`\`
✅ **Non-TLS** : 
\`\`\`
${ssNTls}
\`\`\`



━━━━━━━━━━━━━━━━━━━━━━━
[WEB FREE VPN](https://tunneling.bmkg.xyz)
🚀 **ORDER PREMIUM CONTACT ADMIN**  
[ADMIN TELE](https://t.me/kcepu877)  
[ADMIN WA](https://wa.me/6281335135082)  

`;

  await sendTelegramMessage(chatId, message);
}
 
async function handleTurahCreation(chatId, ip, port, isp) {
  
  const UUIDS = "aaaaaaa1-bbbb-4ccc-accc-eeeeeeeeeee1";  // Perbaiki UUID tanpa backtick yang berlebihan
  const path = `/Free-CF-Proxy-${ip}-${port}`;

  // Konfigurasi Link VPN
  const ssTls = `ss://${btoa(`none:${UUIDS}`)}@tunneling.turah.my.id:443?encryption=none&type=ws&host=tunneling.turah.my.id&path=${encodeURIComponent(path)}&security=tls&sni=tunneling.turah.my.id#${isp}`;
  const ssNTls = `ss://${btoa(`none:${UUIDS}`)}@tunneling.turah.my.id:80?encryption=none&type=ws&host=tunneling.turah.my.id&path=${encodeURIComponent(path)}&security=none&sni=tunneling.turah.my.id#${isp}`;
  const vlessTLS = `vless://${UUIDS}@tunneling.turah.my.id:443?path=${encodeURIComponent(path)}&security=tls&host=tunneling.turah.my.id&type=ws&sni=tunneling.turah.my.id#${isp}`;
  const vlessNTLS = `vless://${UUIDS}@tunneling.turah.my.id:80?path=${encodeURIComponent(path)}&security=none&host=tunneling.turah.my.id&type=ws&sni=tunneling.turah.my.id#${isp}`;
  const trojanTLS = `trojan://${UUIDS}@tunneling.turah.my.id:443?path=${encodeURIComponent(path)}&security=tls&host=tunneling.turah.my.id&type=ws&sni=tunneling.turah.my.id#${isp}`;
  const trojanNTLS = `trojan://${UUIDS}@tunneling.turah.my.id:80?path=${encodeURIComponent(path)}&security=none&host=tunneling.turah.my.id&type=ws&sni=tunneling.turah.my.id#${isp}`;

  
      const message = `
Success Create Vpn Server 
🌍 \`${isp}\` \n⚜️ \`${ip}:${port}\` ⚜️
⚜️ **VPN Configurations** ⚜️

━━━━━━━━━━━━━━━━━━━━━━━
🔗 **VLESS** 
━━━━━━━━━━━━━━━━━━━━━━━
✅ **TLS** : 
\`\`\`
${vlessTLS}
\`\`\`
✅ **Non-TLS** : 
\`\`\`
${vlessNTLS}
\`\`\`


━━━━━━━━━━━━━━━━━━━━━━━
🔗 **Trojan** 
━━━━━━━━━━━━━━━━━━━━━━━
✅ **TLS** : 
\`\`\`
${trojanTLS}
\`\`\`
✅ **Non-TLS** : 
\`\`\`
${trojanNTLS}
\`\`\`


━━━━━━━━━━━━━━━━━━━━━━━
🔗 **ShadowSocks** 
━━━━━━━━━━━━━━━━━━━━━━━
✅ **TLS** : 
\`\`\`
${ssTls}
\`\`\`
✅ **Non-TLS** : 
\`\`\`
${ssNTls}
\`\`\`



━━━━━━━━━━━━━━━━━━━━━━━
[WEB FREE VPN](https://tunneling.bmkg.xyz)
🚀 **ORDER PREMIUM CONTACT ADMIN**  
[ADMIN TELE](https://t.me/kcepu877)  
[ADMIN WA](https://wa.me/6281335135082)  

`;

  await sendTelegramMessage(chatId, message);
}
 
async function handleNajahCreation(chatId, ip, port, isp) {
  
  const UUIDS = "aaaaaaa1-bbbb-4ccc-accc-eeeeeeeeeee1";  // Perbaiki UUID tanpa backtick yang berlebihan
  const path = `/Free-CF-Proxy-${ip}-${port}`;

  // Konfigurasi Link VPN
  const ssTls = `ss://${btoa(`none:${UUIDS}`)}@tunneling.najah.biz.id:443?encryption=none&type=ws&host=tunneling.najah.biz.id&path=${encodeURIComponent(path)}&security=tls&sni=tunneling.najah.biz.id#${isp}`;
  const ssNTls = `ss://${btoa(`none:${UUIDS}`)}@tunneling.najah.biz.id:80?encryption=none&type=ws&host=tunneling.najah.biz.id&path=${encodeURIComponent(path)}&security=none&sni=tunneling.najah.biz.id#${isp}`;
  const vlessTLS = `vless://${UUIDS}@tunneling.najah.biz.id:443?path=${encodeURIComponent(path)}&security=tls&host=tunneling.najah.biz.id&type=ws&sni=tunneling.najah.biz.id#${isp}`;
  const vlessNTLS = `vless://${UUIDS}@tunneling.najah.biz.id:80?path=${encodeURIComponent(path)}&security=none&host=tunneling.najah.biz.id&type=ws&sni=tunneling.najah.biz.id#${isp}`;
  const trojanTLS = `trojan://${UUIDS}@tunneling.najah.biz.id:443?path=${encodeURIComponent(path)}&security=tls&host=tunneling.najah.biz.id&type=ws&sni=tunneling.najah.biz.id#${isp}`;
  const trojanNTLS = `trojan://${UUIDS}@tunneling.najah.biz.id:80?path=${encodeURIComponent(path)}&security=none&host=tunneling.najah.biz.id&type=ws&sni=tunneling.najah.biz.id#${isp}`;

  
      const message = `
Success Create Vpn Server 
🌍 \`${isp}\` \n⚜️ \`${ip}:${port}\` ⚜️
⚜️ **VPN Configurations** ⚜️

━━━━━━━━━━━━━━━━━━━━━━━
🔗 **VLESS** 
━━━━━━━━━━━━━━━━━━━━━━━
✅ **TLS** : 
\`\`\`
${vlessTLS}
\`\`\`
✅ **Non-TLS** : 
\`\`\`
${vlessNTLS}
\`\`\`


━━━━━━━━━━━━━━━━━━━━━━━
🔗 **Trojan** 
━━━━━━━━━━━━━━━━━━━━━━━
✅ **TLS** : 
\`\`\`
${trojanTLS}
\`\`\`
✅ **Non-TLS** : 
\`\`\`
${trojanNTLS}
\`\`\`


━━━━━━━━━━━━━━━━━━━━━━━
🔗 **ShadowSocks** 
━━━━━━━━━━━━━━━━━━━━━━━
✅ **TLS** : 
\`\`\`
${ssTls}
\`\`\`
✅ **Non-TLS** : 
\`\`\`
${ssNTls}
\`\`\`



━━━━━━━━━━━━━━━━━━━━━━━
[WEB FREE VPN](https://tunneling.bmkg.xyz)
🚀 **ORDER PREMIUM CONTACT ADMIN**  
[ADMIN TELE](https://t.me/kcepu877)  
[ADMIN WA](https://wa.me/6281335135082)  

`;

  await sendTelegramMessage(chatId, message);
}
 
async function handleCoudproxyCreation(chatId, ip, port, isp) {
  
  const UUIDS = "aaaaaaa1-bbbb-4ccc-accc-eeeeeeeeeee1";  // Perbaiki UUID tanpa backtick yang berlebihan
  const path = `/Free-CF-Proxy-${ip}-${port}`;

  // Konfigurasi Link VPN
  const ssTls = `ss://${btoa(`none:${UUIDS}`)}@tunneling.cloudproxyip.my.id:443?encryption=none&type=ws&host=tunneling.cloudproxyip.my.id&path=${encodeURIComponent(path)}&security=tls&sni=tunneling.cloudproxyip.my.id#${isp}`;
  const ssNTls = `ss://${btoa(`none:${UUIDS}`)}@tunneling.cloudproxyip.my.id:80?encryption=none&type=ws&host=tunneling.cloudproxyip.my.id&path=${encodeURIComponent(path)}&security=none&sni=tunneling.cloudproxyip.my.id#${isp}`;
  const vlessTLS = `vless://${UUIDS}@tunneling.cloudproxyip.my.id:443?path=${encodeURIComponent(path)}&security=tls&host=tunneling.cloudproxyip.my.id&type=ws&sni=tunneling.cloudproxyip.my.id#${isp}`;
  const vlessNTLS = `vless://${UUIDS}@tunneling.cloudproxyip.my.id:80?path=${encodeURIComponent(path)}&security=none&host=tunneling.cloudproxyip.my.id&type=ws&sni=tunneling.cloudproxyip.my.id#${isp}`;
  const trojanTLS = `trojan://${UUIDS}@tunneling.cloudproxyip.my.id:443?path=${encodeURIComponent(path)}&security=tls&host=tunneling.cloudproxyip.my.id&type=ws&sni=tunneling.cloudproxyip.my.id#${isp}`;
  const trojanNTLS = `trojan://${UUIDS}@tunneling.cloudproxyip.my.id:80?path=${encodeURIComponent(path)}&security=none&host=tunneling.cloudproxyip.my.id&type=ws&sni=tunneling.cloudproxyip.my.id#${isp}`;

  
      const message = `
Success Create Vpn Server 
🌍 \`${isp}\` \n⚜️ \`${ip}:${port}\` ⚜️
⚜️ **VPN Configurations** ⚜️

━━━━━━━━━━━━━━━━━━━━━━━
🔗 **VLESS** 
━━━━━━━━━━━━━━━━━━━━━━━
✅ **TLS** : 
\`\`\`
${vlessTLS}
\`\`\`
✅ **Non-TLS** : 
\`\`\`
${vlessNTLS}
\`\`\`


━━━━━━━━━━━━━━━━━━━━━━━
🔗 **Trojan** 
━━━━━━━━━━━━━━━━━━━━━━━
✅ **TLS** : 
\`\`\`
${trojanTLS}
\`\`\`
✅ **Non-TLS** : 
\`\`\`
${trojanNTLS}
\`\`\`


━━━━━━━━━━━━━━━━━━━━━━━
🔗 **ShadowSocks** 
━━━━━━━━━━━━━━━━━━━━━━━
✅ **TLS** : 
\`\`\`
${ssTls}
\`\`\`
✅ **Non-TLS** : 
\`\`\`
${ssNTls}
\`\`\`



━━━━━━━━━━━━━━━━━━━━━━━
[WEB FREE VPN](https://tunneling.bmkg.xyz)
🚀 **ORDER PREMIUM CONTACT ADMIN**  
[ADMIN TELE](https://t.me/kcepu877)  
[ADMIN WA](https://wa.me/6281335135082)  

`;

  await sendTelegramMessage(chatId, message);
}
 
async function handleXhamsterCreation(chatId, ip, port, isp) {
  
  const UUIDS = "aaaaaaa1-bbbb-4ccc-accc-eeeeeeeeeee1";  // Perbaiki UUID tanpa backtick yang berlebihan
  const path = `/Free-CF-Proxy-${ip}-${port}`;

  // Konfigurasi Link VPN
  const ssTls = `ss://${btoa(`none:${UUIDS}`)}@tunneling.xhamster.biz.id:443?encryption=none&type=ws&host=tunneling.xhamster.biz.id&path=${encodeURIComponent(path)}&security=tls&sni=tunneling.xhamster.biz.id#${isp}`;
  const ssNTls = `ss://${btoa(`none:${UUIDS}`)}@tunneling.xhamster.biz.id:80?encryption=none&type=ws&host=tunneling.xhamster.biz.id&path=${encodeURIComponent(path)}&security=none&sni=tunneling.xhamster.biz.id#${isp}`;
  const vlessTLS = `vless://${UUIDS}@tunneling.xhamster.biz.id:443?path=${encodeURIComponent(path)}&security=tls&host=tunneling.xhamster.biz.id&type=ws&sni=tunneling.xhamster.biz.id#${isp}`;
  const vlessNTLS = `vless://${UUIDS}@tunneling.xhamster.biz.id:80?path=${encodeURIComponent(path)}&security=none&host=tunneling.xhamster.biz.id&type=ws&sni=tunneling.xhamster.biz.id#${isp}`;
  const trojanTLS = `trojan://${UUIDS}@tunneling.xhamster.biz.id:443?path=${encodeURIComponent(path)}&security=tls&host=tunneling.xhamster.biz.id&type=ws&sni=tunneling.xhamster.biz.id#${isp}`;
  const trojanNTLS = `trojan://${UUIDS}@tunneling.xhamster.biz.id:80?path=${encodeURIComponent(path)}&security=none&host=tunneling.xhamster.biz.id&type=ws&sni=tunneling.xhamster.biz.id#${isp}`;

  
      const message = `
Success Create Vpn Server 
🌍 \`${isp}\` \n⚜️ \`${ip}:${port}\` ⚜️
⚜️ **VPN Configurations** ⚜️

━━━━━━━━━━━━━━━━━━━━━━━
🔗 **VLESS** 
━━━━━━━━━━━━━━━━━━━━━━━
✅ **TLS** : 
\`\`\`
${vlessTLS}
\`\`\`
✅ **Non-TLS** : 
\`\`\`
${vlessNTLS}
\`\`\`


━━━━━━━━━━━━━━━━━━━━━━━
🔗 **Trojan** 
━━━━━━━━━━━━━━━━━━━━━━━
✅ **TLS** : 
\`\`\`
${trojanTLS}
\`\`\`
✅ **Non-TLS** : 
\`\`\`
${trojanNTLS}
\`\`\`


━━━━━━━━━━━━━━━━━━━━━━━
🔗 **ShadowSocks** 
━━━━━━━━━━━━━━━━━━━━━━━
✅ **TLS** : 
\`\`\`
${ssTls}
\`\`\`
✅ **Non-TLS** : 
\`\`\`
${ssNTls}
\`\`\`



━━━━━━━━━━━━━━━━━━━━━━━
[WEB FREE VPN](https://tunneling.bmkg.xyz)
🚀 **ORDER PREMIUM CONTACT ADMIN**  
[ADMIN TELE](https://t.me/kcepu877)  
[ADMIN WA](https://wa.me/6281335135082)  

`;

  await sendTelegramMessage(chatId, message);
}
 
async function handleCepuCreation(chatId, ip, port, isp) {
  
  const UUIDS = "aaaaaaa1-bbbb-4ccc-accc-eeeeeeeeeee1";  // Perbaiki UUID tanpa backtick yang berlebihan
  const path = `/Free-CF-Proxy-${ip}-${port}`;

  // Konfigurasi Link VPN
  const ssTls = `ss://${btoa(`none:${UUIDS}`)}@tunneling.cepu.us.kg:443?encryption=none&type=ws&host=tunneling.cepu.us.kg&path=${encodeURIComponent(path)}&security=tls&sni=tunneling.cepu.us.kg#${isp}`;
  const ssNTls = `ss://${btoa(`none:${UUIDS}`)}@tunneling.cepu.us.kg:80?encryption=none&type=ws&host=tunneling.cepu.us.kg&path=${encodeURIComponent(path)}&security=none&sni=tunneling.cepu.us.kg#${isp}`;
  const vlessTLS = `vless://${UUIDS}@tunneling.cepu.us.kg:443?path=${encodeURIComponent(path)}&security=tls&host=tunneling.cepu.us.kg&type=ws&sni=tunneling.cepu.us.kg#${isp}`;
  const vlessNTLS = `vless://${UUIDS}@tunneling.cepu.us.kg:80?path=${encodeURIComponent(path)}&security=none&host=tunneling.cepu.us.kg&type=ws&sni=tunneling.cepu.us.kg#${isp}`;
  const trojanTLS = `trojan://${UUIDS}@tunneling.cepu.us.kg:443?path=${encodeURIComponent(path)}&security=tls&host=tunneling.cepu.us.kg&type=ws&sni=tunneling.cepu.us.kg#${isp}`;
  const trojanNTLS = `trojan://${UUIDS}@tunneling.cepu.us.kg:80?path=${encodeURIComponent(path)}&security=none&host=tunneling.cepu.us.kg&type=ws&sni=tunneling.cepu.us.kg#${isp}`;

  
      const message = `
Success Create Vpn Server 
🌍 \`${isp}\` \n⚜️ \`${ip}:${port}\` ⚜️
⚜️ **VPN Configurations** ⚜️

━━━━━━━━━━━━━━━━━━━━━━━
🔗 **VLESS** 
━━━━━━━━━━━━━━━━━━━━━━━
✅ **TLS** : 
\`\`\`
${vlessTLS}
\`\`\`
✅ **Non-TLS** : 
\`\`\`
${vlessNTLS}
\`\`\`


━━━━━━━━━━━━━━━━━━━━━━━
🔗 **Trojan** 
━━━━━━━━━━━━━━━━━━━━━━━
✅ **TLS** : 
\`\`\`
${trojanTLS}
\`\`\`
✅ **Non-TLS** : 
\`\`\`
${trojanNTLS}
\`\`\`


━━━━━━━━━━━━━━━━━━━━━━━
🔗 **ShadowSocks** 
━━━━━━━━━━━━━━━━━━━━━━━
✅ **TLS** : 
\`\`\`
${ssTls}
\`\`\`
✅ **Non-TLS** : 
\`\`\`
${ssNTls}
\`\`\`



━━━━━━━━━━━━━━━━━━━━━━━
[WEB FREE VPN](https://tunneling.bmkg.xyz)
🚀 **ORDER PREMIUM CONTACT ADMIN**  
[ADMIN TELE](https://t.me/kcepu877)  
[ADMIN WA](https://wa.me/6281335135082)  

`;

  await sendTelegramMessage(chatId, message);
}
 
async function handleKereCreation(chatId, ip, port, isp) {
  
  const UUIDS = "aaaaaaa1-bbbb-4ccc-accc-eeeeeeeeeee1";  // Perbaiki UUID tanpa backtick yang berlebihan
  const path = `/Free-CF-Proxy-${ip}-${port}`;

  // Konfigurasi Link VPN
  const ssTls = `ss://${btoa(`none:${UUIDS}`)}@tunneling.kere.us.kg:443?encryption=none&type=ws&host=tunneling.kere.us.kg&path=${encodeURIComponent(path)}&security=tls&sni=tunneling.kere.us.kg#${isp}`;
  const ssNTls = `ss://${btoa(`none:${UUIDS}`)}@tunneling.kere.us.kg:80?encryption=none&type=ws&host=tunneling.kere.us.kg&path=${encodeURIComponent(path)}&security=none&sni=tunneling.kere.us.kg#${isp}`;
  const vlessTLS = `vless://${UUIDS}@tunneling.kere.us.kg:443?path=${encodeURIComponent(path)}&security=tls&host=tunneling.kere.us.kg&type=ws&sni=tunneling.kere.us.kg#${isp}`;
  const vlessNTLS = `vless://${UUIDS}@tunneling.kere.us.kg:80?path=${encodeURIComponent(path)}&security=none&host=tunneling.kere.us.kg&type=ws&sni=tunneling.kere.us.kg#${isp}`;
  const trojanTLS = `trojan://${UUIDS}@tunneling.kere.us.kg:443?path=${encodeURIComponent(path)}&security=tls&host=tunneling.kere.us.kg&type=ws&sni=tunneling.kere.us.kg#${isp}`;
  const trojanNTLS = `trojan://${UUIDS}@tunneling.kere.us.kg:80?path=${encodeURIComponent(path)}&security=none&host=tunneling.kere.us.kg&type=ws&sni=tunneling.kere.us.kg#${isp}`;

  
      const message = `
Success Create Vpn Server 
🌍 \`${isp}\` \n⚜️ \`${ip}:${port}\` ⚜️
⚜️ **VPN Configurations** ⚜️

━━━━━━━━━━━━━━━━━━━━━━━
🔗 **VLESS** 
━━━━━━━━━━━━━━━━━━━━━━━
✅ **TLS** : 
\`\`\`
${vlessTLS}
\`\`\`
✅ **Non-TLS** : 
\`\`\`
${vlessNTLS}
\`\`\`


━━━━━━━━━━━━━━━━━━━━━━━
🔗 **Trojan** 
━━━━━━━━━━━━━━━━━━━━━━━
✅ **TLS** : 
\`\`\`
${trojanTLS}
\`\`\`
✅ **Non-TLS** : 
\`\`\`
${trojanNTLS}
\`\`\`


━━━━━━━━━━━━━━━━━━━━━━━
🔗 **ShadowSocks** 
━━━━━━━━━━━━━━━━━━━━━━━
✅ **TLS** : 
\`\`\`
${ssTls}
\`\`\`
✅ **Non-TLS** : 
\`\`\`
${ssNTls}
\`\`\`



━━━━━━━━━━━━━━━━━━━━━━━
[WEB FREE VPN](https://tunneling.bmkg.xyz)
🚀 **ORDER PREMIUM CONTACT ADMIN**  
[ADMIN TELE](https://t.me/kcepu877)  
[ADMIN WA](https://wa.me/6281335135082)  

`;

  await sendTelegramMessage(chatId, message);
}
 
async function handleXnxxxCreation(chatId, ip, port, isp) {
  
  const UUIDS = "aaaaaaa1-bbbb-4ccc-accc-eeeeeeeeeee1";  // Perbaiki UUID tanpa backtick yang berlebihan
  const path = `/Free-CF-Proxy-${ip}-${port}`;

  // Konfigurasi Link VPN
  const ssTls = `ss://${btoa(`none:${UUIDS}`)}@tunneling.zifxoyfpuf0uf0ycphcoyf0684wd.us.kg:443?encryption=none&type=ws&host=tunneling.zifxoyfpuf0uf0ycphcoyf0684wd.us.kg&path=${encodeURIComponent(path)}&security=tls&sni=tunneling.zifxoyfpuf0uf0ycphcoyf0684wd.us.kg#${isp}`;
  const ssNTls = `ss://${btoa(`none:${UUIDS}`)}@tunneling.zifxoyfpuf0uf0ycphcoyf0684wd.us.kg:80?encryption=none&type=ws&host=tunneling.zifxoyfpuf0uf0ycphcoyf0684wd.us.kg&path=${encodeURIComponent(path)}&security=none&sni=tunneling.zifxoyfpuf0uf0ycphcoyf0684wd.us.kg#${isp}`;
  const vlessTLS = `vless://${UUIDS}@tunneling.zifxoyfpuf0uf0ycphcoyf0684wd.us.kg:443?path=${encodeURIComponent(path)}&security=tls&host=tunneling.zifxoyfpuf0uf0ycphcoyf0684wd.us.kg&type=ws&sni=tunneling.zifxoyfpuf0uf0ycphcoyf0684wd.us.kg#${isp}`;
  const vlessNTLS = `vless://${UUIDS}@tunneling.zifxoyfpuf0uf0ycphcoyf0684wd.us.kg:80?path=${encodeURIComponent(path)}&security=none&host=tunneling.zifxoyfpuf0uf0ycphcoyf0684wd.us.kg&type=ws&sni=tunneling.zifxoyfpuf0uf0ycphcoyf0684wd.us.kg#${isp}`;
  const trojanTLS = `trojan://${UUIDS}@tunneling.zifxoyfpuf0uf0ycphcoyf0684wd.us.kg:443?path=${encodeURIComponent(path)}&security=tls&host=tunneling.zifxoyfpuf0uf0ycphcoyf0684wd.us.kg&type=ws&sni=tunneling.zifxoyfpuf0uf0ycphcoyf0684wd.us.kg#${isp}`;
  const trojanNTLS = `trojan://${UUIDS}@tunneling.zifxoyfpuf0uf0ycphcoyf0684wd.us.kg:80?path=${encodeURIComponent(path)}&security=none&host=tunneling.zifxoyfpuf0uf0ycphcoyf0684wd.us.kg&type=ws&sni=tunneling.zifxoyfpuf0uf0ycphcoyf0684wd.us.kg#${isp}`;

  
      const message = `
Success Create Vpn Server 
🌍 \`${isp}\` \n⚜️ \`${ip}:${port}\` ⚜️
⚜️ **VPN Configurations** ⚜️

━━━━━━━━━━━━━━━━━━━━━━━
🔗 **VLESS** 
━━━━━━━━━━━━━━━━━━━━━━━
✅ **TLS** : 
\`\`\`
${vlessTLS}
\`\`\`
✅ **Non-TLS** : 
\`\`\`
${vlessNTLS}
\`\`\`


━━━━━━━━━━━━━━━━━━━━━━━
🔗 **Trojan** 
━━━━━━━━━━━━━━━━━━━━━━━
✅ **TLS** : 
\`\`\`
${trojanTLS}
\`\`\`
✅ **Non-TLS** : 
\`\`\`
${trojanNTLS}
\`\`\`


━━━━━━━━━━━━━━━━━━━━━━━
🔗 **ShadowSocks** 
━━━━━━━━━━━━━━━━━━━━━━━
✅ **TLS** : 
\`\`\`
${ssTls}
\`\`\`
✅ **Non-TLS** : 
\`\`\`
${ssNTls}
\`\`\`


━━━━━━━━━━━━━━━━━━━━━━━
[WEB FREE VPN](https://tunneling.bmkg.xyz)
🚀 **ORDER PREMIUM CONTACT ADMIN**  
[ADMIN TELE](https://t.me/kcepu877)  
[ADMIN WA](https://wa.me/6281335135082)  

`;

  await sendTelegramMessage(chatId, message);
}
 

async function sendInlineKeyboard(chatId, ip, port, isp) {
  try {
    const response = await fetch(`${TELEGRAM_API_URL}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: chatId,
        text: 'Pilih opsi berikut untuk membuat VPN Tunnel:',
        reply_markup: {
          inline_keyboard: [

            [
              { text: '🌐 bmkg.xyz', callback_data: `create_bmkg|${ip}|${port}|${isp}` },
            ],
                        [
              { text: 'Server ndeso.xyz', callback_data: `create_ndeso|${ip}|${port}|${isp}` },
            ],
                        [
              { text: '🌐 ndeso.web.id', callback_data: `create_ndeso1|${ip}|${port}|${isp}` },
            ],
                        [
              { text: '🌐 turah.my.id', callback_data: `create_turah|${ip}|${port}|${isp}` },
            ],
                        [
              { text: '🌐 najah.biz.id', callback_data: `create_najah|${ip}|${port}|${isp}` },
            ],
                        [
              { text: '🌐 cloudproxyip.my.id', callback_data: `create_coudproxy|${ip}|${port}|${isp}` },
            ],
                        [
              { text: '🌐 xhamster.biz.id', callback_data: `create_xhamster|${ip}|${port}|${isp}` },
            ],
                        [
              { text: '🌐 cepu.us.kg', callback_data: `create_cepu|${ip}|${port}|${isp}` },
            ],
                        [
              { text: '🌐 kere.us.kg', callback_data: `create_kere|${ip}|${port}|${isp}` },
            ],
                        [
              { text: '🌐 zifxoyfpuf0uf0ycphcoyf0684wd.us.kg', callback_data: `create_xnxxx|${ip}|${port}|${isp}` },
            ],
          ],
        },
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('Failed to send inline keyboard:', errorText);
    } else {
      console.log('Inline keyboard sent successfully.');
    }
  } catch (error) {
    console.error('Error sending inline keyboard:', error);
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
        return {proxyIP, proxyPort, country, org };
      });
    }
  }
  return cachedProxyList;
}

function getAllConfig(hostName, proxyList) {
  const encodePath = (proxyIP, proxyPort) => {
    // Remove spaces and then encode
    const cleanedProxyIP = proxyIP.trim(); // Remove leading and trailing spaces
    return `%2F${encodeURIComponent(cleanedProxyIP)}%3D${encodeURIComponent(proxyPort)}`;
  };

  const encodeSpace = (string) => {
    return encodeURIComponent(string).replace(/\s+/g, ''); // Remove spaces entirely
  };

  const proxyListElements = proxyList.map(({ proxyIP, proxyPort, country, org }, index) => {
    const pathcode = encodePath(proxyIP, proxyPort);
    const encodedCountry = encodeSpace(country);
    const encodedOrg = encodeSpace(org);
    

    const status = `${proxyIP}:${proxyPort}`;
    const vlessTls = `vless://${UUIDS}@tunneling.bmkg.xyz:443?encryption=none&security=tls&sni=tunneling.bmkg.xyz&fp=randomized&type=ws&host=tunneling.bmkg.xyz&path=/Free-CF-Proxy-${proxyIP}-${proxyPort}#(${encodedCountry})${encodedOrg}-[Tls]`;
    const vlessNTls = `vless://${UUIDS}@tunneling.bmkg.xyz:80?encryption=none&security=none&sni=tunneling.bmkg.xyz&fp=randomized&type=ws&host=tunneling.bmkg.xyz&path=/Free-CF-Proxy-${proxyIP}-${proxyPort}#(${encodedCountry})${encodedOrg}-[NTls]`;
    const trojanTls = `trojan://${UUIDS}@tunneling.bmkg.xyz:443?encryption=none&security=tls&sni=tunneling.bmkg.xyz&fp=randomized&type=ws&host=tunneling.bmkg.xyz&path=/Free-CF-Proxy-${proxyIP}-${proxyPort}#(${encodedCountry})${encodedOrg}-[Tls]`;
    const trojanNTls = `trojan://${UUIDS}@tunneling.bmkg.xyz:80?encryption=none&security=none&sni=tunneling.bmkg.xyz&fp=randomized&type=ws&host=tunneling.bmkg.xyz&path=/Free-CF-Proxy-${proxyIP}-${proxyPort}#(${encodedCountry})${encodedOrg}-[NTls]`;
    const ssTls = `ss://${btoa(`none:${UUIDS}`)}@tunneling.bmkg.xyz:443?encryption=none&type=ws&host=tunneling.bmkg.xyz&path=/Free-CF-Proxy-${proxyIP}-${proxyPort}&security=tls&sni=tunneling.bmkg.xyz#${encodedCountry}${encodedOrg}-[Tls]`;
    const ssNTls = `ss://${btoa(`none:${UUIDS}`)}@tunneling.bmkg.xyz:80?encryption=none&type=ws&host=tunneling.bmkg.xyz&path=/Free-CF-Proxy-${proxyIP}-${proxyPort}&security=none&sni=tunneling.bmkg.xyz#${encodedCountry}${encodedOrg}-[NTls]`;
    const clashVLTls = `
#Free VPN
proxies:
- name: (${country}) ${org}-[Tls]-[VL]
  server: tunneling.bmkg.xyz
  port: 443
  type: vless
  uuid: ${UUIDS}
  cipher: auto
  tls: true
  client-fingerprint: chrome
  udp: true
  skip-cert-verify: true
  network: ws
  servername: tunneling.bmkg.xyz
  alpn:
    - h2
    - h3
    - http/1.1
  ws-opts:
    path: /Free-CF-Proxy-${proxyIP}-${proxyPort}
    headers:
      Host: tunneling.bmkg.xyz
    max-early-data: 0
    early-data-header-name: Sec-WebSocket-Protocol
    ip-version: dual
    v2ray-http-upgrade: false
    v2ray-http-upgrade-fast-open: false
    `;

    const clashTRTls =`
#Free VPN
proxies:      
- name: (${country}) ${org}-[Tls]-[TR]
  server: tunneling.bmkg.xyz
  port: 443
  type: trojan
  password: ${UUIDS}
  tls: true
  client-fingerprint: chrome
  udp: true
  skip-cert-verify: true
  network: ws
  sni: tunneling.bmkg.xyz
  alpn:
    - h2
    - h3
    - http/1.1
  ws-opts:
    path: /Free-CF-Proxy-${proxyIP}-${proxyPort}
    headers:
      Host: tunneling.bmkg.xyz
    max-early-data: 0
    early-data-header-name: Sec-WebSocket-Protocol
    ip-version: dual
    v2ray-http-upgrade: false
    v2ray-http-upgrade-fast-open: false
    `;

    const clashSSTls =`
#Free VPN
proxies:
- name: (${country}) ${org}-[Tls]-[SS]
  server: tunneling.bmkg.xyz
  port: 443
  type: ss
  cipher: none
  password: ${UUIDS}
  plugin: v2ray-plugin
  client-fingerprint: chrome
  udp: true
  plugin-opts:
    mode: websocket
    host: tunneling.bmkg.xyz
    path: /Free-CF-Proxy-${proxyIP}-${proxyPort}
    tls: true
    mux: false
    skip-cert-verify: true
  headers:
    custom: value
    ip-version: dual
    v2ray-http-upgrade: false
    v2ray-http-upgrade-fast-open: false
    `;
    const escapedClashSSTls = clashSSTls.replace(/\n/g, '\\n').replace(/"/g, '\\"');
    const escapedClashVLTls = clashVLTls.replace(/\n/g, '\\n').replace(/"/g, '\\"');
    const escapedClashTRTls = clashTRTls.replace(/\n/g, '\\n').replace(/"/g, '\\"');
    
    // Combine all configurations into one string
    const allconfigs = [
      ssTls,
      ssNTls,
      vlessTls,
      vlessNTls,
      trojanTls,
      trojanNTls,
    ].join('\n\n');
    
    // Encode the string for use in JavaScript
    const encodedAllconfigs = encodeURIComponent(allconfigs);
    
    
    return `
      <div class="content ${index === 0 ? "active" : ""}">
        <h2>Free-VPN</h2>
        <hr class="config-divider" />
        <h2>VLESS TROJAN SHADOWSOCKS</h2>
        <h2>CloudFlare</h2>
        <hr class="config-divider"/>
        <h1><strong> Country : </strong>${country} </h1>
        <h1><strong> Country : </strong>${org} </h1>
        <h1><strong> ProxyIP : </strong>${proxyIP}:${proxyPort}</h1>
        <button class="button" onclick="fetchAndDisplayAlert('${status}')">Proxy Status</button>
    
        <hr class="config-divider" />
    
        <strong><h2>VLESS</h2></strong>
        <h1>Vless Tls</h1>
        <pre>${vlessTls}</pre>
        <button onclick="copyToClipboard('${vlessTls}')">Copy Vless TLS</button><br>
        <h1>Vless NTls</h1>
        <pre>${vlessNTls}</pre>
        <button onclick="copyToClipboard('${vlessNTls}')">Copy Vless N-TLS</button><br>
        <h1>Clash Vless TLS</h1>
        <pre>${clashVLTls}</pre>
    
        <hr class="config-divider" />
    
        <strong><h2>TROJAN</h2></strong>
        <h1>Trojan TLS</h1>
        <pre>${trojanTls}</pre>
        <button onclick="copyToClipboard('${trojanTls}')">Copy Trojan TLS</button>
        <h1>Trojan N-TLS</h1>
        <pre>${trojanNTls}</pre>
        <button onclick="copyToClipboard('${trojanNTls}')">Copy Trojan N-TLS</button>
        <h1>Clash Trojan TLS</h1>
        <pre>${clashTRTls}</pre>
    
        <hr class="config-divider" />
    
        <strong><h2>SHADOWSOCKS</h2></strong>
        <h1>Shadowsocks TLS</h1>
        <pre>${ssTls}</pre>
        <button onclick="copyToClipboard('${ssTls}')">Copy Shadowsocks TLS</button>
        <h1>Shadowsocks N-TLS</h1>
        <pre>${ssNTls}</pre>
        <button onclick="copyToClipboard('${ssNTls}')">Copy Shadowsocks N-TLS</button>
        <h1>Clash Shadowsocks TLS</h1>
        <pre>${clashSSTls}</pre>
    
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
      <title>Free-VPN | VPN Tunnel | CloudFlare</title>
      
      <!-- SEO Meta Tags -->
      <meta name="description" content="Akun Vless Gratis. Free-VPN offers free Vless accounts with Cloudflare and Trojan support. Secure and fast VPN tunnel services.">
      <meta name="keywords" content="Free-VPN, Free Vless, Vless CF, Trojan CF, Cloudflare, VPN Tunnel, Akun Vless Gratis">
      <meta name="author" content="Free-VPN">
      <meta name="robots" content="index, follow"> <!-- Enable search engines to index the page -->
      <meta name="robots" content="noarchive"> <!-- Prevent storing a cached version of the page -->
      <meta name="robots" content="max-snippet:-1, max-image-preview:large, max-video-preview:-1"> <!-- Improve visibility in search snippets -->
      
      <!-- Social Media Meta Tags -->
      <meta property="og:title" content="Free-VPN | Free Vless & Trojan Accounts">
      <meta property="og:description" content="Free-VPN provides free Vless accounts and VPN tunnels via Cloudflare. Secure, fast, and easy setup.">
      <meta property="og:image" content="https://raw.githubusercontent.com/akulelaki696/bg/refs/heads/main/20250106_010158.jpg"> <!-- Image to appear in previews -->
      <meta property="og:url" content="https://vip.rtmq.fun"> <!-- Your website URL -->
      <meta property="og:type" content="website">
      <meta property="og:site_name" content="Free-VPN">
      <meta property="og:locale" content="en_US"> <!-- Set to your language/locale -->
      
      <!-- Twitter Card Meta Tags -->
      <meta name="twitter:card" content="summary_large_image">
      <meta name="twitter:title" content="Free-VPN | Free Vless & Trojan Accounts">
      <meta name="twitter:description" content="Get free Vless accounts and fast VPN services via Cloudflare with Free-VPN. Privacy and security guaranteed.">
      <meta name="twitter:image" content="https://raw.githubusercontent.com/akulelaki696/bg/refs/heads/main/20250106_010158.jpg"> <!-- Image for Twitter -->
      <meta name="twitter:site" content="@Free VPN">
      <meta name="twitter:creator" content="@Free VPN">
      
      <!-- Telegram Meta Tags -->
      <meta property="og:image:type" content="image/jpeg"> <!-- Specify the image type for Telegram and other platforms -->
      <meta property="og:image:secure_url" content="https://raw.githubusercontent.com/akulelaki696/bg/refs/heads/main/20250106_010158.jpg"> <!-- Secure URL for image -->
      <meta property="og:audio" content="URL-to-audio-if-any"> <!-- Optionally add audio for Telegram previews -->
      <meta property="og:video" content="URL-to-video-if-any"> <!-- Optionally add video for Telegram previews -->
      
      <!-- Additional Meta Tags -->
      <meta name="theme-color" content="#000000"> <!-- Mobile browser theme color -->
      <meta name="format-detection" content="telephone=no"> <!-- Prevent automatic phone number detection -->
      <meta name="generator" content="Free-VPN">
      <meta name="google-site-verification" content="google-site-verification-code"> <!-- Google verification -->
      
      <!-- Open Graph Tags for Rich Links -->
      <meta property="og:image:width" content="1200">
      <meta property="og:image:height" content="630">
      <meta property="og:image:alt" content="Free-VPN Image Preview">
      
      <!-- Favicon and Icon links -->
      <link rel="icon" href="https://raw.githubusercontent.com/AFRcloud/BG/main/icons8-film-noir-80.png" type="image/png">
      <link rel="apple-touch-icon" href="https://raw.githubusercontent.com/AFRcloud/BG/main/icons8-film-noir-80.png">
      <link rel="manifest" href="/manifest.json">
        

      
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
        background-color: rgba(0, 0, 0, 0.0);
        backdrop-filter: blur(5px);
        display: grid;
        grid-template-columns: 1.5fr 3fr;
        overflow: hidden;
        animation: popupEffect 1s ease-in-out;
      }
    
      @keyframes popupEffect {
        0% { transform: scale(0.8); opacity: 0; }
        100% { transform: scale(1); opacity: 1; }
      }
    
      .tabs {
        background-color: rgba(0, 0, 0, 0.0);
        padding: 10px;
        display: flex;
        flex-direction: column;
        gap: 6px;
        overflow-y: auto;
        overflow-x: hidden;
        border-right: 5px solid #00FFFF;
        box-shadow: inset 0 0 15px rgba(0, 255, 255, 0.3);
      }
    
      .author-link {
        position: absolute;
        bottom: 10px;
        right: 10px;
        font-weight: bold;
        font-style: italic;
        color: #00FFFF;
        font-size: 1rem;
        text-decoration: none;
        z-index: 10;
      }
    
      .author-link:hover {
        color: #0FF;
        text-shadow: 0px 0px 10px rgba(0, 255, 255, 0.8);
      }
    
      label {
        font-size: 14px;
        cursor: pointer;
        color: #00FFFF;
        padding: 12px;
        background: linear-gradient(90deg, #000, #333);
        border-radius: 10px;
        text-align: left;
        transition: background 0.3s ease, transform 0.3s ease;
        box-shadow: 0px 4px 8px rgba(0, 255, 255, 0.4);
        white-space: normal;
        overflow-wrap: break-word;
      }
    
      label:hover {
        background: #00FFFF;
        color: #000;
        transform: translateY(-4px);
        box-shadow: 0px 8px 16px rgba(0, 255, 255, 0.2);
      }
    
      input[type="radio"] {
        display: none;
      }
    
      .tab-content {
        padding: 0px 0px 0px 10px;
        overflow-y: auto;
        color: #00FFFF;
        font-size: 12px;
        background-color: rgba(0, 0, 0, 0.8);
        height: 100%;
        box-sizing: border-box;
        border-radius: 10px;
        box-shadow: inset 0 0 20px rgba(0, 255, 255, 0.2);
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
        color: #00FFFF;
        margin-bottom: 10px;
        text-shadow: 0px 0px 10px rgba(0, 255, 255, 0.5);
      }
    
      h2 {
        font-size: 22px;
        color: #00FFFF;
        text-align: center;
        text-shadow: 0px 0px 10px rgba(0, 255, 255, 0.5);
        font-weight: 500;
        text-transform: uppercase;
        letter-spacing: 8px;
      }
    
      pre {
        background-color: rgba(0, 0, 0, 0.2);
        padding: 5px;
        border-radius: 5px;
        font-size: 12px;
        white-space: pre-wrap;
        word-wrap: break-word;
        color: #00FFFF;
        border: 1px solid #00FFFF;
        box-shadow: 0px 6px 10px rgba(0, 255, 255, 0.4);
      }
    
      .config-divider {
        border: none;
        height: 2px;
        background: linear-gradient(to right, transparent, #00FFFF, transparent);
        margin: 40px 0;
      }
    
      .config-description {
        font-weight: bold;
        font-style: italic;
        color: #00FFFF;
        font-size: 14px;
        text-align: justify;
        margin: 0 10px;
      }
    
      button {
        padding: 9px 12px;
        border: none;
        border-radius: 5px;
        background-color: #00FFFF;
        color: #111;
        cursor: pointer;
        font-weight: bold;
        display: block;
        text-align: left;
        box-shadow: 0px 6px 10px rgba(0, 255, 255, 0.4);
        transition: background-color 0.3s ease, transform 0.3s ease;
      }
    
      button:hover {
        background-color: #0FF;
        transform: translateY(-3px);
        box-shadow: 0px 6px 10px rgba(0, 255, 255, 0.4);
      }
    
      #search {
        background: #333;
        color: #00FFFF;
        border: 1px solid #00FFFF;
        border-radius: 6px;
        padding: 5px;
        margin-bottom: 10px;
        width: 100%;
        box-shadow: 0px 4px 8px rgba(0, 255, 255, 0.3);
      }
    
      #search::placeholder {
        color: #00FFFF;
      }
    
      .watermark {
        position: absolute;
        bottom: 10px;
        left: 50%;
        transform: translateX(-50%);
        font-size: 1rem;
        color: #00FFFF;
        text-shadow: 1px 1px 2px rgba(0, 0, 0, 0.5);
        font-weight: bold;
        text-align: center;
      }
    
      .watermark a {
        color: #00FFFF;
        text-decoration: none;
        font-weight: bold;
      }
    
      .watermark a:hover {
        color: #00FFFF;
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
              <label for="tab${index}" class="tab-label" data-country="${country.toLowerCase()}">${org} (${country})</label>
            `
          )
          .join("")}
      </div>
      <div class="tab-content">${proxyListElements}</div>
    </div>
    <br>
    <a href="https://t.me/kcepu_bot" class="watermark" target="_blank">Free-Bot</a>
    <a href="https://t.me/kstore877" class="author-link" target="_blank">Free-VPN</a>
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
            showPopup("Copied to clipboard!");
        })
        .catch((err) => {
            console.error("Failed to copy to clipboard:", err);
        });
  }

  function fetchAndDisplayAlert(path) {
    fetch(path)
        .then(response => {
            if (!response.ok) {
                throw new Error(\`HTTP error! Status: \${response.status}\`);
            }
            return response.json();
        })
        .then(data => {
            const status = data.status || "Unknown status";
            showPopup(\`Proxy Status: \${status}\`);
        })
        .catch((err) => {
            alert("Failed to fetch data or invalid response.");
        });
  }

  function showPopup(message) {
    const popup = document.createElement('div');
    popup.textContent = message;
    popup.style.position = 'fixed';
    popup.style.top = '10%';
    popup.style.left = '50%';
    popup.style.transform = 'translate(-50%, -50%)'; // Center the popup
    popup.style.backgroundColor = 'rgba(0, 255, 255, 0.8)'; // Neon Blue Transparent Background
    popup.style.color = 'black';
    popup.style.padding = '10px';
    popup.style.border = '3px solid black';
    popup.style.fontSize = '14px';
    popup.style.width = '130px'; // Consistent width
    popup.style.height = '20px'; // Consistent height
    popup.style.borderRadius = '15px'; // Rounded corners
    popup.style.boxShadow = '0 10px 20px rgba(0, 0, 0, 0.3)'; // Strong shadow for depth
    popup.style.opacity = '0';
    popup.style.transition = 'opacity 0.5s ease, transform 0.5s ease'; // Smooth transitions for opacity and transform
    popup.style.display = 'flex';
    popup.style.alignItems = 'center';
    popup.style.justifyContent = 'center';
    popup.style.textAlign = 'center';
    popup.style.zIndex = '1000'; // Ensure it's on top

    // Adding a little bounce animation when it appears
    popup.style.transform = 'translate(-50%, -50%) scale(0.5)'; // Start smaller for zoom effect
    document.body.appendChild(popup);

    // Apply animation for smooth transition
    setTimeout(() => {
        popup.style.opacity = '1';
        popup.style.transform = 'translate(-50%, -50%) scale(1)'; // Zoom in effect
    }, 100);

    // Hide the popup after 2 seconds
    setTimeout(() => {
        popup.style.opacity = '0';
        popup.style.transform = 'translate(-50%, -50%) scale(0.5)'; // Shrink back for zoom effect
        setTimeout(() => {
            document.body.removeChild(popup);
        }, 100); // Remove the popup after animation ends
    }, 3000);
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
