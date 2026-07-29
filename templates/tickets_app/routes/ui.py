"""학생이 실제로 '써보는' 프론트엔드 (실전성) — 고객지원 티켓 앱. JSON API 를 그대로 호출.

취약 핸들러(routes/tickets.py 의 get_ticket·search.py·db.py)는 건드리지 않는다. 이 파일은
슬롯 대상이 아니며, 브라우저가 학생 권한으로 호출할 수 있는 API 만 부른다. 렌더는 전부 textContent.

인증은 notes 와 달리 X-User-Token 헤더를 쓴다. IDOR 흐름은 notes 와 동일:
  - '내 티켓' 목록엔 내 소유 티켓만 보인다. 남의 티켓은 목록에 없다.
  - 하드는 티켓 번호가 랜덤이라 못 찍음 → GET /tickets 목록 응답이 워크스페이스 전체 번호를
    흘리는 걸 알아채 피해자 번호를 얻은 뒤 열어야 한다(유출 발견 → 악용 2단계).
  - 검색(공개)은 SQLi 표면 — 깨진 쿼리는 원 오류를 그대로 보여줘 탐침 → 악용.
"""

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter()

_PAGE = """<!doctype html>
<html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>HelpDesk — 지원 티켓</title>
<style>
  :root{--bg:#f6f7f9;--card:#fff;--line:#e3e6ea;--ink:#1f2328;--muted:#6b7280;--brand:#0f7b6c;--danger:#c0392b}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Noto Sans KR",sans-serif}
  header{background:var(--card);border-bottom:1px solid var(--line);padding:14px 20px;display:flex;align-items:center;gap:12px}
  header .logo{font-weight:800;font-size:18px}
  header .sp{margin-left:auto}
  main{max-width:860px;margin:0 auto;padding:22px 20px 60px}
  .panel{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin-bottom:20px}
  h2{font-size:13px;letter-spacing:.04em;text-transform:uppercase;color:var(--muted);margin:0 0 12px}
  input,button{font:inherit}
  input[type=text],input[type=password],input[type=number]{width:100%;padding:9px 12px;border:1px solid var(--line);border-radius:8px;background:#fff}
  .row{display:flex;gap:8px}
  button{cursor:pointer;border:1px solid var(--line);background:#fff;border-radius:8px;padding:9px 14px;font-weight:600}
  button.primary{background:var(--brand);border-color:var(--brand);color:#fff}
  .note{border:1px solid var(--line);border-radius:10px;padding:12px 14px;margin-top:10px;cursor:pointer;display:flex;align-items:center;gap:10px}
  .note:hover{border-color:var(--brand);box-shadow:0 1px 6px rgba(15,123,108,.12)}
  .note .id{font:600 12px ui-monospace,Menlo,monospace;color:var(--muted);min-width:34px}
  .note .t{font-weight:600;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .badge{font-size:11px;padding:2px 8px;border-radius:20px;border:1px solid var(--line);color:var(--muted)}
  .badge.priv{color:#8a5a00;border-color:#e8d9b0;background:#fff8e6}
  .hint{color:var(--muted);font-size:13px;margin:6px 0 0}
  .out{white-space:pre-wrap;word-break:break-word;background:#0f172a;color:#e2e8f0;border-radius:8px;padding:12px 14px;font:13px/1.5 ui-monospace,Menlo,monospace;margin-top:10px;display:none}
  .out.err{background:#2b1416;color:#fecaca}
  .detail{margin-top:12px;border-top:1px dashed var(--line);padding-top:12px;display:none}
  .detail .body{margin-top:8px;padding:12px 14px;background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;white-space:pre-wrap}
  .small{font-size:12px;color:var(--muted)}
  .w120{max-width:140px}
</style></head>
<body>
<header>
  <span class="logo">🎫 HelpDesk</span>
  <span class="small" id="who">비로그인</span>
  <span class="sp"></span>
  <button id="logout" style="display:none">로그아웃</button>
</header>
<main>

  <div class="panel">
    <h2>티켓 검색</h2>
    <div class="row">
      <input type="text" id="q" placeholder="제목으로 검색… (예: 결제)" autocomplete="off" spellcheck="false">
      <button class="primary" id="searchBtn">검색</button>
    </div>
    <p class="hint">공개 티켓을 제목으로 찾습니다.</p>
    <div class="out" id="searchOut"></div>
  </div>

  <div class="panel">
    <h2>내 티켓</h2>
    <div id="loginBox">
      <p class="hint">내 티켓을 보려면 액세스 토큰으로 로그인하세요.</p>
      <div class="row">
        <input type="password" id="token" placeholder="액세스 토큰" autocomplete="off" spellcheck="false">
        <button class="primary" id="loginBtn">로그인</button>
      </div>
      <p class="hint" id="loginErr" style="color:var(--danger);display:none"></p>
    </div>
    <div id="myTickets" style="display:none"></div>
  </div>

  <div class="panel" id="openerPanel" style="display:none">
    <h2>티켓 바로가기</h2>
    <p class="hint">티켓 번호를 알고 있다면 바로 엽니다.</p>
    <div class="row">
      <input type="number" id="openId" class="w120" placeholder="티켓 번호" min="1">
      <button id="openBtn">열기</button>
    </div>
    <div class="detail" id="detail"></div>
  </div>

</main>
<script>
"use strict";
const $=id=>document.getElementById(id);
const KEY="hd_token";
let token=localStorage.getItem(KEY)||"";
let me=null;               // {id,name}
let ticketMeta={};         // id -> {owner_id,is_confidential,subject}

function authHeaders(){ return token?{"X-User-Token":token}:{}; }
function el(tag,cls,txt){ const e=document.createElement(tag); if(cls)e.className=cls; if(txt!=null)e.textContent=txt; return e; }
async function req(path,opts){
  const res=await fetch(path,opts); const raw=await res.text();
  let data=null; try{data=JSON.parse(raw);}catch(e){}
  return {ok:res.ok,status:res.status,data,raw};
}

// ---- 검색(공개, 로그인 불필요) ----
async function search(path){
  const out=$("searchOut"); out.style.display="block"; out.className="out"; out.textContent="검색 중…";
  const {ok,status,data,raw}=await req(path);
  if(!ok){ out.className="out err"; out.textContent="HTTP "+status+"\\n"+raw; return; }
  const rows=(data&&data.results)||[]; out.className="out";
  out.textContent=rows.length?rows.map(r=>"#"+r.id+"  "+r.subject).join("\\n"):"(결과 없음)";
}
$("searchBtn").onclick=()=>search("/tickets/search?q="+encodeURIComponent($("q").value));
$("q").addEventListener("keydown",e=>{if(e.key==="Enter")$("searchBtn").click();});

// ---- 로그인 / 내 티켓 ----
function setAuthUI(){
  const on=!!me;
  $("who").textContent=on?(me.name+" (id "+me.id+")"):"비로그인";
  $("logout").style.display=on?"":"none";
  $("loginBox").style.display=on?"none":"";
  $("myTickets").style.display=on?"":"none";
  $("openerPanel").style.display=on?"":"none";
}
async function login(){
  const raw=$("token").value.trim();
  if(!raw)return;
  token=raw;
  const who=await req("/me",{headers:authHeaders()});
  if(!who.ok){ $("loginErr").style.display="block"; $("loginErr").textContent="로그인 실패 (HTTP "+who.status+") — 토큰을 확인하세요."; token=""; return; }
  me=who.data; localStorage.setItem(KEY,token); $("loginErr").style.display="none"; setAuthUI(); loadMyTickets();
}
function logout(){ token=""; me=null; ticketMeta={}; localStorage.removeItem(KEY); $("detail").style.display="none"; setAuthUI(); }
$("loginBtn").onclick=login;
$("token").addEventListener("keydown",e=>{if(e.key==="Enter")login();});
$("logout").onclick=logout;

async function loadMyTickets(){
  const {ok,data}=await req("/tickets",{headers:authHeaders()});
  if(!ok){ logout(); return; }
  ticketMeta={}; (data||[]).forEach(t=>{ ticketMeta[t.id]=t; });
  const all=(data||[]); const mine=all.filter(t=>me&&t.owner_id===me.id);
  renderMyTickets(mine, all.length);
}
function renderMyTickets(mine, total){
  const box=$("myTickets"); box.textContent="";
  if(!mine.length){ box.appendChild(el("p","hint","(등록한 티켓이 없습니다)")); }
  mine.forEach(t=>{
    const card=el("div","note");
    card.appendChild(el("span","id","#"+t.id));
    card.appendChild(el("span","t",t.subject));
    card.appendChild(el("span",t.is_confidential?"badge priv":"badge",t.is_confidential?"🔒 기밀":"공개"));
    card.onclick=()=>openTicket(t.id);
    box.appendChild(card);
  });
  // 워크스페이스 개요 스탯(실제 제품처럼). 총 티켓 수가 내 티켓보다 많다는 사실 자체가
  // 자연스러운 정보 노출 — 어디서 그 번호를 얻는지는 스스로 파악하게 둔다(스포일러 없음).
  box.appendChild(el("p","hint","워크스페이스 티켓 "+(total||mine.length)+"개 · 내 티켓 "+mine.length+"개"));
}

async function openTicket(id){
  id=parseInt(id,10); if(!id)return;
  const d=$("detail"); d.style.display="block"; d.textContent="";
  const {ok,status,data}=await req("/tickets/"+id,{headers:authHeaders()});
  if(!ok){ d.appendChild(el("div","hint",status===404?"그런 티켓이 없습니다.":status===403?"열람 권한이 없습니다.":"열람 실패 ("+status+")")); return; }
  d.appendChild(el("strong",null,data.subject||("티켓 #"+id)));
  const meta=ticketMeta[id];
  if(meta){ d.appendChild(el("div","hint","등록자 #"+meta.owner_id+(me&&meta.owner_id===me.id?" · 나":""))); }
  d.appendChild(el("div","body",data.description!=null?data.description:"(내용 없음)"));
}
$("openBtn").onclick=()=>openTicket($("openId").value);
$("openId").addEventListener("keydown",e=>{if(e.key==="Enter")openTicket($("openId").value);});

// 초기화: 저장된 토큰이 있으면 신원 복원.
(async()=>{
  if(!token){ setAuthUI(); return; }
  const who=await req("/me",{headers:authHeaders()});
  if(who.ok){ me=who.data; setAuthUI(); loadMyTickets(); } else { logout(); }
})();
</script>
</body></html>"""


@router.get("/", response_class=HTMLResponse)
def index() -> str:
    return _PAGE
