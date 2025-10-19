# 楦中国网站 路 绾潤鎬侀儴缃叉寚鍗?
鏈」鐩负绾墠绔潤鎬佺珯鐐癸紙`index.html + styles.css + script.js + 鏁欑▼ HTML`锛夛紝涓嶄緷璧栧悗绔湇鍔°€備綘鍙互灏嗗畠闆堕厤缃儴缃插埌 GitHub Pages 鎴?Netlify锛屽苟鐩存帴鍏綉璁块棶銆?
## 涓€閿瑙?- 宸插唴缃?GitHub Pages 宸ヤ綔娴侊細`.github/workflows/pages.yml`
- 宸插唴缃?Netlify 閰嶇疆锛歚netlify.toml`
- 宸叉坊鍔?`.nojekyll` 浠ラ伩鍏?Jekyll 澶勭悊
- 鍒嗕韩地址鐢熸垚閫昏緫宸查€傞厤鍏綉鎵樼涓庡瓙璺緞锛圙itHub 椤圭洰绔欑偣锛?
---

## 閮ㄧ讲鍒?GitHub Pages锛堟帹鑽愶級
1) 鍦?GitHub 鍒涘缓涓€涓粨搴擄紙Public 鎴?Private with Pages锛夛紝渚嬪锛歚yourname/niaoguo-site`
2) 鍦ㄦ湰鍦版墽琛屼互涓嬪懡浠わ紙PowerShell锛夛細

```powershell
# 鍒濆鍖栧苟鎺ㄩ€佸埌 GitHub锛堝皢 <YOUR_REMOTE_URL> 鏇挎崲涓轰綘鐨勪粨搴撳湴鍧€锛? git init
 git add .
 git commit -m "Init static site"
 git branch -M main
 git remote add origin <YOUR_REMOTE_URL>
 git push -u origin main
```

3) 浠撳簱璁剧疆 -> Pages -> Source 閫夋嫨 GitHub Actions锛岄粯璁や細鑷姩浣跨敤 `pages.yml` 鍙戝竷銆?4) 鎴愬姛鍚庝細寰楀埌绔欑偣地址锛?- 用户涓婚〉锛歚https://<username>.github.io/`
- 椤圭洰绔欑偣锛歚https://<username>.github.io/<repo>/`

> 提示锛氬鏋滀綘浣跨敤椤圭洰绔欑偣锛堝甫瀛愯矾寰勶級锛岀珯鍐呯殑鈥滃眬鍩熺綉鍒嗕韩鈥濇樉绀轰細鍖呭惈瀹為檯瀛愯矾寰勶紝复制鍗崇敤銆?
---

## 閮ㄧ讲鍒?Netlify
1) 鐧诲綍 Netlify锛岄€夋嫨 鈥淎dd new site鈥?-> 鈥淚mport from Git鈥濓紝缁戝畾浣犵殑 GitHub 浠撳簱銆?2) Build 鍛戒护鐣欑┖锛堟湰椤圭洰涓虹函闈欐€侊級锛孭ublish directory 浣跨敤鏍圭洰褰曪紙宸插湪 `netlify.toml` 鎸囧畾涓?`.`锛夈€?3) 閮ㄧ讲瀹屾垚鍚庡嵆鍙幏寰楃珯鐐?URL锛屽彲鍦?Netlify 涓粦瀹氳嚜瀹氫箟鍩熴€?
---

## 鑷畾涔夊煙涓?HTTPS
- GitHub Pages锛氫粨搴撹缃?-> Pages -> Custom domain锛屾寜提示鍦ㄤ綘鐨?DNS 服务鍟嗘坊鍔?CNAME 璁板綍銆?- Netlify锛氬湪鍩熷悕绠＄悊涓坊鍔犵珯鐐瑰煙锛屽皢 DNS 鎸囧悜 Netlify锛屾垨浣跨敤 CNAME 鍒板垎閰嶇殑瀛愬煙銆?
---

## 鍙€変紭鍖栵紙闈炲繀闇€锛?- `.gitignore`锛氬涓嶅笇鏈涗笂浼犺緝澶х殑浜岃繘鍒舵枃浠讹紝鍙湪鏈湴娣诲姞濡備笅鏉＄洰鍚庡啀鎻愪氦锛?  ```gitignore
  *.exe
  *.dll
  niao/
  disasm.txt
  report.txt
  ```
- 閾炬帴鍋ュ．鎬э細濡傞渶瑕侀€傞厤鏇村镜像鎴栧湴鍖鸿闂紝鍙湪 `script.js` 涓负鐗瑰畾鏉＄洰娣诲姞 `mirrors` 瀛楁骞舵覆鏌撱€?- SEO锛氬闇€璋冩暣 `<link rel="canonical">` 浠ュ尮閰嶄綘鐨勮嚜瀹氫箟鍩燂紝鍙湪 `index.html` 涓洿鏂般€?
---

## 鏈湴棰勮
鍦ㄩ」鐩洰褰曡繍琛岋細
```powershell
python -m http.server 8000
```
璁块棶 `http://localhost:8000/` 杩涜鏈湴棰勮銆?
---

濡傞渶鎴戜负浣犲垱寤轰粨搴撳苟鎺ㄩ€侊紝鎴栫紪鍐欒嚜鍔ㄥ寲鑴氭湰锛堝惈浠撳簱 URL 娉ㄥ叆锛夛紝鍛婅瘔鎴戜綘鐨?GitHub 浠撳簱地址鍗冲彲銆

