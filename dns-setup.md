鍩熷悕缁戝畾涓庡姞閫熼厤缃紙shaniao.com锛?
鐩爣锛氬皢 `shaniao.com` 缁戝畾鍒?GitHub Pages锛堢敤鎴峰悕 `yuan145408`锛夛紝骞跺彲閫夋帴鍏?Cloudflare 鍋?CDN 涓?301 璺宠浆銆?
涓€銆佸垹闄ら敊璇褰曪紙鍦ㄤ綘鐨勫煙鍚?DNS 鎺у埗鍙帮級
- 鍒犻櫎 `@` 鐨?`A 119.29.209.32`
- 鍒犻櫎 `www` 鐨?`A 122.114.41.145`
- 鑻ュ瓨鍦ㄥ叾浠栦笌 GitHub/Cloudflare 鏃犲叧鐨?`A/AAAA`锛屼竴骞剁Щ闄ゃ€?
浜屻€佹纭褰曪紙鐩存帴鎸囧悜 GitHub Pages锛?- 涓绘満 `@`锛堟牴鍩燂級锛氭坊鍔?4 鏉?`A` 璁板綍锛圱TL 600锛?  - 185.199.108.153
  - 185.199.109.153
  - 185.199.110.153
  - 185.199.111.153
- 涓绘満 `www`锛氭坊鍔?`CNAME`锛圱TL 600锛?  - `www -> yuan145408.github.io`

涓夈€佷粨搴撹缃紙GitHub Pages锛?- 鍦ㄤ粨搴?`Settings -> Pages`锛?  - `Custom domain` 濉啓锛歚shaniao.com`
  - 鍕鹃€?`Enforce HTTPS`
- 浠撳簱宸插寘鍚?`CNAME` 文件锛堝唴瀹癸細`shaniao.com`锛夛紝淇濇寔涓嶅彉銆?
鍥涖€佸彲閫夛細Cloudflare 鍔犻€熶笌 301 瑙勮寖锛堟帹鑽愶級
1) 灏嗗煙鍚嶇殑 NS 鍒囨崲鍒?Cloudflare 鎻愪緵鐨勪袱鍙板悕绉版湇鍔″櫒锛堝湪娉ㄥ唽鍟嗘搷浣滐級銆?2) Cloudflare DNS锛堝潎寮€鍚浜戜唬鐞?Proxied锛夛細
   - `@`锛歚CNAME -> yuan145408.github.io`锛圕loudflare 浼氳嚜鍔?CNAME Flatten 鍒?A锛?   - `www`锛歚CNAME -> yuan145408.github.io`
3) Cloudflare SSL/TLS锛?   - 妯″紡閫夋嫨 `Full`
   - 寮€鍚?`Always Use HTTPS` 涓?`Automatic HTTPS Rewrites`
4) Cloudflare 閲嶅畾鍚戣鍒欙紙301锛夛細
   - 瑙勫垯锛歚www.shaniao.com/*` 姘镐箙閲嶅畾鍚戝埌 `https://shaniao.com/$1`
   - 鍙€夛細灏嗘墍鏈?`http://*` 閲嶅畾鍚戝埌 `https://$1`

浜斻€佽嚜妫€锛圖NS/璇佷功鐢熸晥閫氬父闇€瑕?5鈥?0 鍒嗛挓锛屽伓灏旀洿涔咃級
- PowerShell 鑷锛?  - `Resolve-DnsName shaniao.com` 搴旀樉绀?GitHub/Cloudflare 鐩爣锛堜笉鍐嶆槸 `119.29.209.32`锛夈€?  - `Resolve-DnsName www.shaniao.com` 搴旀樉绀?`CNAME -> yuan145408.github.io`銆?  - `Test-NetConnection -ComputerName shaniao.com -Port 443` 搴斾负 `TcpTestSucceeded : True`銆?- 娴忚鍣細
  - 璁块棶 `https://www.shaniao.com/` 搴?301 鍒?`https://shaniao.com/`锛堝鍚敤 Cloudflare 瑙勫垯锛夈€?  - 璁块棶 `https://shaniao.com/` 姝ｅ父杩斿洖椤甸潰锛屼笖鏄剧ず HTTPS 閿佹爣璇嗐€?
鍏€佷复鏃惰闂紙鍦?DNS/璇佷功鏈敓鏁堟湡闂达級
- 浣跨敤 `https://yuan145408.github.io/<浣犵殑浠撳簱鍚?/` 杩涜娴嬭瘯锛涚敓鏁堝悗缁熶竴鐢?`https://shaniao.com/`銆

