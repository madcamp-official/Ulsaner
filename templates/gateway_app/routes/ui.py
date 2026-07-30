"""학생용 프론트엔드 — URL 상태 확인 도구(웹훅 테스터). JSON API 를 그대로 호출.

취약 핸들러(gateway.fetch 의 내부 URL 차단)는 건드리지 않는다. SSRF 2-hop 피벗:
  1. /status 에서 내부 서비스 존재를 파악.
  2. /fetch 로 서버가 대신 요청 → 내부 URL(/internal/services)에 피벗 → vault_token 획득.
  3. 그 토큰으로 /fetch → /internal/vault?token=... 2차 피벗 → flag.
"""

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter()

_PAGE = """<!doctype html>
<html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Gateway — URL 상태 확인</title>
<style>
  :root{--bg:#f6f7f9;--card:#fff;--line:#e3e6ea;--ink:#1f2328;--muted:#6b7280;--brand:#0891b2;--danger:#c0392b}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Noto Sans KR",sans-serif}
  header{background:var(--card);border-bottom:1px solid var(--line);padding:14px 20px;display:flex;align-items:center;gap:10px}
  header .logo{font-weight:800;font-size:18px}
  main{max-width:800px;margin:0 auto;padding:22px 20px 60px}
  .panel{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 18px;margin-bottom:16px}
  h2{font-size:13px;letter-spacing:.04em;text-transform:uppercase;color:var(--muted);margin:0 0 10px}
  input{width:100%;padding:9px 12px;border:1px solid var(--line);border-radius:8px;background:#fff;font:inherit}
  .row{display:flex;gap:8px}
  button{cursor:pointer;border:1px solid var(--line);background:#fff;border-radius:8px;padding:9px 14px;font-weight:600;font:inherit}
  button.primary{background:var(--brand);border-color:var(--brand);color:#fff}
  .hint{color:var(--muted);font-size:12.5px;margin:6px 0 0}
  .out{white-space:pre-wrap;word-break:break-word;background:#0f172a;color:#e2e8f0;border-radius:8px;padding:12px 14px;font:12px/1.6 ui-monospace,Menlo,monospace;margin-top:12px;display:none}
</style></head>
<body>
<header><span class="logo">🌐 Gateway</span><span class="hint" style="margin:0">URL 상태 확인 도구</span></header>
<main>
  <div class="panel">
    <h2>서비스 상태</h2>
    <button id="statusBtn">GET /status</button>
  </div>
  <div class="panel">
    <h2>URL 가져오기 (웹훅 테스터)</h2>
    <div class="row">
      <input id="url" placeholder="https://example.com" autocomplete="off" spellcheck="false">
      <button class="primary" id="fetchBtn" style="white-space:nowrap">가져오기</button>
    </div>
    <p class="hint">입력한 URL 을 서버가 대신 요청해 응답을 보여줍니다.</p>
  </div>
  <div class="out" id="out"></div>
</main>
<script>
"use strict";
const $=id=>document.getElementById(id);
async function req(path,opts){ const r=await fetch(path,opts); const raw=await r.text(); let d=null; try{d=JSON.parse(raw);}catch(e){} return {ok:r.ok,status:r.status,data:d,raw}; }
function show(x){ const o=$("out"); o.style.display="block"; o.textContent=typeof x==="string"?x:JSON.stringify(x,null,2); }
$("statusBtn").onclick=async()=>{ const {data}=await req("/status"); show(data); };
$("fetchBtn").onclick=async()=>{
  show("요청 중…");
  const {ok,status,data,raw}=await req("/fetch",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({url:$("url").value})});
  show(ok?data:("HTTP "+status+"\\n"+raw));
};
$("url").addEventListener("keydown",e=>{if(e.key==="Enter")$("fetchBtn").click();});
</script>
</body></html>"""


@router.get("/", response_class=HTMLResponse)
def index() -> str:
    return _PAGE
