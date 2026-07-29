"""학생이 실제로 '써보는' 프론트엔드 — 포인트 상점. JSON API 를 그대로 호출.

취약 핸들러(routes/store.py 의 purchase)는 건드리지 않는다. 이 파일은 슬롯 대상이 아니며,
브라우저가 학생 권한으로 호출할 수 있는 API 만 부른다. 렌더는 전부 textContent.

비즈니스 로직 결함: 구매는 총액 = 가격 × 수량 으로 잔액을 검사한다. 수량 양수 검증이
빠지면(슬롯), 수량을 음수로 넣어 총액을 음수로 만들어 잔액 검사를 통과 → 프리미엄 상품
(리워드=flag)을 '살 수 있다'. dirbusting·인젝션 없이 앱 규칙을 논리로 깨는 문제.
"""

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter()

_PAGE = """<!doctype html>
<html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>PointShop — 포인트 상점</title>
<style>
  :root{--bg:#f6f7f9;--card:#fff;--line:#e3e6ea;--ink:#1f2328;--muted:#6b7280;--brand:#7c3aed;--danger:#c0392b;--ok:#0f7b6c}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Noto Sans KR",sans-serif}
  header{background:var(--card);border-bottom:1px solid var(--line);padding:14px 20px;display:flex;align-items:center;gap:12px}
  header .logo{font-weight:800;font-size:18px}
  header .sp{margin-left:auto}
  .bal{font-weight:700;color:var(--brand)}
  main{max-width:760px;margin:0 auto;padding:22px 20px 60px}
  .panel{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin-bottom:20px}
  h2{font-size:13px;letter-spacing:.04em;text-transform:uppercase;color:var(--muted);margin:0 0 12px}
  input,button{font:inherit}
  input[type=text],input[type=password],input[type=number]{width:100%;padding:9px 12px;border:1px solid var(--line);border-radius:8px;background:#fff}
  .row{display:flex;gap:8px;align-items:center}
  button{cursor:pointer;border:1px solid var(--line);background:#fff;border-radius:8px;padding:9px 14px;font-weight:600}
  button.primary{background:var(--brand);border-color:var(--brand);color:#fff}
  .item{border:1px solid var(--line);border-radius:10px;padding:14px;margin-top:10px;display:flex;align-items:center;gap:12px}
  .item .name{font-weight:700;flex:1}
  .item .price{font:600 13px ui-monospace,Menlo,monospace;color:var(--muted)}
  .item input{width:88px}
  .hint{color:var(--muted);font-size:13px;margin:6px 0 0}
  .out{white-space:pre-wrap;word-break:break-word;border-radius:8px;padding:12px 14px;margin-top:12px;display:none;font-size:14px}
  .out.ok{background:#f0fdf4;border:1px solid #bbf7d0;color:var(--ok)}
  .out.err{background:#fff5f5;border:1px solid #fed7d7;color:var(--danger)}
  .reward{margin-top:8px;padding:10px 14px;background:#faf5ff;border:1px solid #e9d5ff;border-radius:8px;font-weight:700}
  .w120{max-width:160px}
</style></head>
<body>
<header>
  <span class="logo">🛒 PointShop</span>
  <span class="small" id="who" style="font-size:12px;color:var(--muted)">비로그인</span>
  <span class="sp"></span>
  <span id="balBox" style="display:none">잔액 <span class="bal" id="bal">–</span> P</span>
  <button id="logout" style="display:none;margin-left:12px">로그아웃</button>
</header>
<main>

  <div class="panel" id="loginPanel">
    <h2>로그인</h2>
    <p class="hint">액세스 토큰으로 로그인하세요.</p>
    <div class="row">
      <input type="password" id="token" placeholder="액세스 토큰" autocomplete="off" spellcheck="false">
      <button class="primary w120" id="loginBtn">로그인</button>
    </div>
    <p class="hint" id="loginErr" style="color:var(--danger);display:none"></p>
  </div>

  <div class="panel" id="shopPanel" style="display:none">
    <h2>상품</h2>
    <div id="items"></div>
    <div class="out" id="out"></div>
  </div>

</main>
<script>
"use strict";
const $=id=>document.getElementById(id);
const KEY="ps_token";
let token=localStorage.getItem(KEY)||"";
let me=null;

function authHeaders(extra){ return Object.assign(token?{Authorization:"Bearer "+token}:{}, extra||{}); }
function el(tag,cls,txt){ const e=document.createElement(tag); if(cls)e.className=cls; if(txt!=null)e.textContent=txt; return e; }
async function req(path,opts){
  const res=await fetch(path,opts); const raw=await res.text();
  let data=null; try{data=JSON.parse(raw);}catch(e){}
  return {ok:res.ok,status:res.status,data,raw};
}

function setUI(){
  const on=!!me;
  $("who").textContent=on?me.name:"비로그인";
  $("balBox").style.display=on?"":"none";
  $("logout").style.display=on?"":"none";
  $("loginPanel").style.display=on?"none":"";
  $("shopPanel").style.display=on?"":"none";
  if(on) $("bal").textContent=me.balance;
}
async function login(){
  const raw=$("token").value.trim().replace(/^Bearer\\s+/i,"");
  if(!raw)return;
  token=raw;
  const who=await req("/me",{headers:authHeaders()});
  if(!who.ok){ $("loginErr").style.display="block"; $("loginErr").textContent="로그인 실패 (HTTP "+who.status+")"; token=""; return; }
  me=who.data; localStorage.setItem(KEY,token); $("loginErr").style.display="none"; setUI(); loadItems();
}
function logout(){ token=""; me=null; localStorage.removeItem(KEY); setUI(); }
$("loginBtn").onclick=login;
$("token").addEventListener("keydown",e=>{if(e.key==="Enter")login();});
$("logout").onclick=logout;

async function loadItems(){
  const box=$("items"); box.textContent="";
  const {ok,data}=await req("/store/items");
  if(!ok){ return; }
  (data||[]).forEach(it=>{
    const row=el("div","item");
    row.appendChild(el("span","name",it.name));
    row.appendChild(el("span","price",it.price+" P"));
    const qty=el("input"); qty.type="number"; qty.value="1"; qty.className="";
    row.appendChild(qty);
    const buy=el("button","primary","구매");
    buy.onclick=()=>purchase(it.id, qty.value);
    row.appendChild(buy);
    box.appendChild(row);
  });
}
async function purchase(itemId, quantity){
  const out=$("out"); out.style.display="block"; out.className="out"; out.textContent="처리 중…";
  const {ok,status,data}=await req("/store/purchase",{
    method:"POST",
    headers:authHeaders({"Content-Type":"application/json"}),
    body:JSON.stringify({item_id:itemId, quantity:parseInt(quantity,10)}),
  });
  if(!ok){
    out.className="out err";
    out.textContent = status===402 ? "잔액이 부족합니다."
      : status===400 ? "수량이 올바르지 않습니다."
      : "구매 실패 (HTTP "+status+")";
    return;
  }
  out.className="out ok";
  out.textContent = data.purchased+" ×"+data.quantity+" 구매 완료 (총 "+data.total+" P)";
  if(data.reward){
    const r=el("div","reward","🎁 리워드: "+data.reward);
    out.appendChild(r);
  }
  // 잔액 갱신
  const who=await req("/me",{headers:authHeaders()});
  if(who.ok){ me=who.data; $("bal").textContent=me.balance; }
}

setUI();
if(token){ (async()=>{ const w=await req("/me",{headers:authHeaders()}); if(w.ok){ me=w.data; setUI(); loadItems(); } else logout(); })(); }
</script>
</body></html>"""


@router.get("/", response_class=HTMLResponse)
def index() -> str:
    return _PAGE
