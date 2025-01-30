// Fungsi untuk menghasilkan UUID v4 varian 2
function generateUUIDv4() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
        var r = Math.random() * 16 | 0,
            v = c === 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
  }
  
  // Fungsi untuk mengambil parameter dari URL
  function getURLParameter(url, name) {
    const urlParams = new URLSearchParams(url);
    return urlParams.get(name);
  }
  
  async function handleRequest(request) {
    const url = new URL(request.url);
  
    // Jika permintaan ke root (https://sub1.bmkg.xyz/), tampilkan halaman HTML
    if (url.pathname === '/') {
        return new Response(`
            <html>
  <script>
  window.location.href = 'http://kang.cepu.us.kg';
  </script>
  
            </html>
        `, {
            headers: { 'Content-Type': 'text/html' }
        });
    }
  
    // Mendukung format /sub1=ID&vless?count=5
    const queryParams = url.pathname.slice(1).split('&');
    let type = null;
  
    // Cari tipe (vless, trojan, ss) dari query params
    for (const param of queryParams) {
        if (['vless', 'trojan', 'ss'].includes(param.toLowerCase())) {
            type = param.toLowerCase();
            break;
        }
    }
  
    if (type) {
        const urlParams = new URLSearchParams(url.search); // Ambil parameter dari query string
        const countryParam1 = urlParams.get('sub1');
        const countryParam2 = urlParams.get('sub2');
        const countParam = urlParams.get('count');
        const count = parseInt(countParam, 10) || 5; // Defaultkan menjadi 5 jika tidak ada atau tidak valid
        const wildcard = urlParams.get('wildcard'); // Ambil wildcard dari URL, jika ada
  
        try {
            // Mengambil data proxy
            const response = await fetch('https://cf.cepu.us.kg/update_proxyip.txt');
            if (!response.ok) throw new Error('Failed to load proxy list.');
            const text = await response.text();
            const proxies = text.split('\n').filter(proxy => proxy.trim() !== '');
  
            // Jika sub1 adalah "RANDOM", pilih proxy secara acak
            // Jika sub1 atau sub2 adalah "RANDOM", pilih proxy secara acak
  let proxiesToShow = [];
  if (countryParam1 === 'RANDOM' || countryParam2 === 'RANDOM') {
    // Pilih proxy secara acak
    for (let i = 0; i < count; i++) {
        const randomProxy = proxies[Math.floor(Math.random() * proxies.length)];
        proxiesToShow.push(randomProxy);
    }
  } else {
    // Filter proxies berdasarkan negara jika sub1 atau sub2 tidak "RANDOM"
    const filteredProxies = proxies.filter(proxy => {
        const [, , country] = proxy.split(',');
        const upperCountry = country.toUpperCase();
        return (countryParam1 && upperCountry === countryParam1.toUpperCase()) ||
               (countryParam2 && upperCountry === countryParam2.toUpperCase());
    });
  
    // Ambil sesuai dengan count
    proxiesToShow = filteredProxies.slice(0, count);
  }
  
  
            const proxyUrls = [];
  
            for (const proxy of proxiesToShow) {
                const [ip, port, country, provider] = proxy.split(',');
                const uuid = generateUUIDv4(); // Menghasilkan UUID v4 varian 2
  
                let urlString = '';
  
                // Tentukan URL sesuai dengan tipe dan sub1/sub2
                if (countryParam1) {
                    // sub1
                    if (type === 'vless') {
                        if (wildcard) {
                            urlString = `vless://${uuid}@${wildcard}:443?encryption=none&type=ws&host=${wildcard}begal.bmkg.xyz&path=%2F${ip}-${port}&security=tls&sni=${wildcard}begal.bmkg.xyz#(${wildcard})${country}+${provider}`;
                        } else {
                            urlString = `vless://${uuid}@begal.bmkg.xyz:443?encryption=none&type=ws&host=begal.bmkg.xyz&path=%2F${ip}-${port}&security=tls&sni=begal.bmkg.xyz#${country}+${provider}`;
                        }
                    } else if (type === 'trojan') {
                        if (wildcard) {
                            urlString = `trojan://${uuid}@${wildcard}:443?encryption=none&type=ws&host=${wildcard}begal.bmkg.xyz&path=%2F${ip}-${port}&security=tls&sni=${wildcard}begal.bmkg.xyz#(${wildcard})${country}+${provider}`;
                        } else {
                            urlString = `trojan://${uuid}@begal.bmkg.xyz:443?encryption=none&type=ws&host=begal.bmkg.xyz&path=%2F${ip}-${port}&security=tls&sni=begal.bmkg.xyz#${country}+${provider}`;
                        }
                    } else if (type === 'ss') {
                        const ssBase64 = btoa('onEto5d2d2a2c5Z3b2E9sbLAAe6bYmD3v8l8fGVbt34='); // Base64 encode SS password (change with your actual password)
                        if (wildcard) {
                            urlString = `ss://bm9uZTo1ZDJlYmQyYS05Y2I5LTRkMWItYWY1NS04NjE3ZDNlODFmMzk%3D@${wildcard}:443?encryption=none&type=ws&host=${wildcard}begal.bmkg.xyz&path=%2F${ip}-${port}&security=tls&sni=${wildcard}begal.bmkg.xyz#(${wildcard})${country}+${provider}`;
                        } else {
                            urlString = `ss://bm9uZTo1ZDJlYmQyYS05Y2I5LTRkMWItYWY1NS04NjE3ZDNlODFmMzk%3D@begal.bmkg.xyz:443?encryption=none&type=ws&host=begal.bmkg.xyz&path=%2F${ip}-${port}&security=tls&sni=begal.bmkg.xyz#${country}+${provider}`;
                        }
                    }
                } else if (countryParam2) {
                    // sub2
                    if (type === 'vless') {
                        if (wildcard) {
                            urlString = `vless://FREE-V2RAY-BMKG-XYZ@${wildcard}:443?encryption=none&type=ws&host=${wildcard}.xvp.bmkg.xyz&path=%2Fvl%3D${ip}%3A${port}&security=tls&sni=${wildcard}.xvp.bmkg.xyz#(${wildcard})${country}+${provider}`;
                        } else {
                            urlString = `vless://FREE-V2RAY-BMKG-XYZ@xvp.bmkg.xyz:443?encryption=none&type=ws&host=xvp.bmkg.xyz&path=%2Fvl%3D${ip}%3A${port}&security=tls&sni=xvp.bmkg.xyz#v${country}+${provider}`;
                        }
                    } else if (type === 'trojan') {
                        if (wildcard) {
                            urlString = `trojan://FREE-V2RAY-BMKG-XYZ@${wildcard}:443?encryption=none&type=ws&host=${wildcard}.xvp.bmkg.xyz&path=%2Ftr%3D${ip}%3A${port}&security=tls&sni=${wildcard}.xvp.bmkg.xyz#(${wildcard})${country}+${provider}`;
                        } else {
                            urlString = `trojan://FREE-V2RAY-BMKG-XYZ@xvp.bmkg.xyz:443?encryption=none&type=ws&host=xvp.bmkg.xyz&path=%2Ftr%3D${ip}%3A${port}&security=tls&sni=xvp.bmkg.xyz#${country}+${provider}`;
                        }
                    }
                }
  
                proxyUrls.push(urlString); // Tambahkan URL ke array
            }
  
            return new Response(proxyUrls.join('\n'), {
                headers: { 'Content-Type': 'text/plain' }
            });
        } catch (error) {
            return new Response('Error loading proxy list', {
                status: 500,
                headers: { 'Content-Type': 'text/plain' }
            });
        }
    }
  
    return new Response('Not Found', { status: 404 });
  }
  
  addEventListener('fetch', event => {
    event.respondWith(handleRequest(event.request));
  });
  
