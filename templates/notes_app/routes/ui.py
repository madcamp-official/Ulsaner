"""학생이 실제로 '써보는' 프론트엔드 (실전성). JSON API를 그대로 호출하는 단일 페이지.

취약 핸들러(routes/notes.py의 get_note·search.py·db.py)는 건드리지 않는다. 이 파일은 슬롯
대상이 아니며, 브라우저가 학생 권한으로 호출할 수 있는 API만 부른다. 렌더는 전부 textContent.

실전형 IDOR 흐름(정답을 손에 쥐여주지 않는다):
  - 로그인 = 그냥 '내 계정'으로 들어오는 것(자격증명은 과제에 명시). 취약점이 아니다.
  - '내 노트' 목록엔 **내 소유 노트만** 보인다. 남의 노트는 목록에 없다.
  - 다른 노트를 보려면 '노트 번호로 열기'에서 id 를 직접 바꿔가며 조회해야 한다.
    권한 없는 남의 비공개 노트가 열리면(본문·flag 노출) = IDOR 를 스스로 발견한 것.
  - 검색(공개)은 SQLi 표면 — 깨진 쿼리는 원 오류를 그대로 보여줘 '탐침 → 악용'.
"""

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter()

# 이 프론트엔드는 취약 앱의 기존 JSON API만 호출한다 — db/인증 모듈을 import 하지 않는다
# (그래야 슬롯·테스트 수집과 완전히 분리된다). '내 노트 vs 남의 노트' 구분은 별도 /me 없이,
# GET /notes(=내 소유 노트만 반환)로 얻은 id 집합으로 판정한다.

_PAGE = """<!doctype html>
<html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Notebook — 개인 노트</title>
<style>
  :root{--bg:#f6f7f9;--card:#fff;--line:#e3e6ea;--ink:#1f2328;--muted:#6b7280;--brand:#2f6feb;--danger:#c0392b;--warn:#b45309}
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
  .note:hover{border-color:var(--brand);box-shadow:0 1px 6px rgba(47,111,235,.12)}
  .note .id{font:600 12px ui-monospace,Menlo,monospace;color:var(--muted);min-width:34px}
  .note .t{font-weight:600;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .badge{font-size:11px;padding:2px 8px;border-radius:20px;border:1px solid var(--line);color:var(--muted)}
  .badge.priv{color:#8a5a00;border-color:#e8d9b0;background:#fff8e6}
  .hint{color:var(--muted);font-size:13px;margin:6px 0 0}
  .out{white-space:pre-wrap;word-break:break-word;background:#0f172a;color:#e2e8f0;border-radius:8px;padding:12px 14px;font:13px/1.5 ui-monospace,Menlo,monospace;margin-top:10px;display:none}
  .out.err{background:#2b1416;color:#fecaca}
  .detail{margin-top:12px;border-top:1px dashed var(--line);padding-top:12px;display:none}
  .detail .path{font:12px ui-monospace,Menlo,monospace;color:var(--muted)}
  .detail .body{margin-top:8px;padding:12px 14px;background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;white-space:pre-wrap}
  .idor{margin-top:10px;padding:10px 14px;border-radius:8px;background:#fffbeb;border:1px solid #fde68a;color:var(--warn);font-weight:600;font-size:13px}
  details summary{cursor:pointer;color:var(--muted);font-size:13px;margin-top:8px}
  .small{font-size:12px;color:var(--muted)}
  .w120{max-width:140px}
</style></head>
<body>
<header>
  <span class="logo">📓 Notebook</span>
  <span class="small" id="who">비로그인</span>
  <span class="sp"></span>
  <button id="logout" style="display:none">로그아웃</button>
</header>
<main>

  <div class="panel">
    <h2>노트 검색</h2>
    <div class="row">
      <input type="text" id="q" placeholder="제목으로 검색… (예: 회의)" autocomplete="off" spellcheck="false">
      <button class="primary" id="searchBtn">검색</button>
    </div>
    <p class="hint">공개 노트를 제목으로 찾습니다.</p>
    <details><summary>고급 검색</summary>
      <div class="row" style="margin-top:8px">
        <input type="text" id="aq" placeholder="q" autocomplete="off" spellcheck="false">
        <input type="text" id="aexclude" placeholder="exclude (제외할 제목)" autocomplete="off" spellcheck="false">
        <button id="advBtn">검색</button>
      </div>
    </details>
    <div class="out" id="searchOut"></div>
  </div>

  <div class="panel">
    <h2>내 노트</h2>
    <div id="loginBox">
      <p class="hint">내 노트를 보려면 액세스 토큰으로 로그인하세요.</p>
      <div class="row">
        <input type="password" id="token" placeholder="액세스 토큰 (예: Bearer token-xxxx 의 token-xxxx)" autocomplete="off" spellcheck="false">
        <button class="primary" id="loginBtn">로그인</button>
      </div>
      <p class="hint" id="loginErr" style="color:var(--danger);display:none"></p>
    </div>
    <div id="myNotes" style="display:none"></div>
  </div>

  <div class="panel" id="openerPanel" style="display:none">
    <h2>노트 열기</h2>
    <p class="hint">노트를 번호로 조회합니다. <code>GET /notes/{번호}</code></p>
    <div class="row">
      <input type="number" id="openId" class="w120" placeholder="노트 번호" min="1">
      <button id="openBtn">열기</button>
    </div>
    <div class="detail" id="detail"></div>
  </div>

</main>
<script>
"use strict";
const $=id=>document.getElementById(id);
const KEY="nb_token";
let token=localStorage.getItem(KEY)||"";
let me=null;               // {id,name} — GET /me (현재 로그인 신원)
let noteMeta={};           // id -> {owner_id,is_private,title} (워크스페이스 메타, 소유자 판정용)

function authHeaders(){ return token?{Authorization:"Bearer "+token}:{}; }
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
  if(!ok){ out.className="out err"; out.textContent="HTTP "+status+"\\n"+raw; return; }  // 깨진 쿼리 원문 = SQLi 탐침 신호
  const rows=(data&&data.results)||[]; out.className="out";
  out.textContent=rows.length?rows.map(r=>"#"+r.id+"  "+r.title).join("\\n"):"(결과 없음)";
}
$("searchBtn").onclick=()=>search("/notes/search?q="+encodeURIComponent($("q").value));
$("q").addEventListener("keydown",e=>{if(e.key==="Enter")$("searchBtn").click();});
$("advBtn").onclick=()=>search("/notes/search/advanced?q="+encodeURIComponent($("aq").value)+"&exclude="+encodeURIComponent($("aexclude").value));

// ---- 로그인 / 내 노트 ----
function setAuthUI(){
  const on=!!me;
  $("who").textContent=on?(me.name+" (id "+me.id+")"):"비로그인";
  $("logout").style.display=on?"":"none";
  $("loginBox").style.display=on?"none":"";
  $("myNotes").style.display=on?"":"none";
  $("openerPanel").style.display=on?"":"none";
}
async function login(){
  const raw=$("token").value.trim().replace(/^Bearer\\s+/i,"");
  if(!raw)return;
  token=raw;
  const who=await req("/me",{headers:authHeaders()});
  if(!who.ok){ $("loginErr").style.display="block"; $("loginErr").textContent="로그인 실패 (HTTP "+who.status+") — 토큰을 확인하세요."; token=""; return; }
  me=who.data; localStorage.setItem(KEY,token); $("loginErr").style.display="none"; setAuthUI(); loadMyNotes();
}
function logout(){ token=""; me=null; noteMeta={}; localStorage.removeItem(KEY); $("detail").style.display="none"; setAuthUI(); }
$("loginBtn").onclick=login;
$("token").addEventListener("keydown",e=>{if(e.key==="Enter")login();});
$("logout").onclick=logout;

async function loadMyNotes(){
  // 워크스페이스 메타는 소유자 판정용으로만 받는다. 화면엔 '내 노트'만 그린다 —
  // 다른 사용자의 노트는 목록에 노출하지 않아, 번호를 직접 바꿔가며 찾아야 한다(발견).
  const {ok,data}=await req("/notes",{headers:authHeaders()});
  if(!ok){ logout(); return; }
  noteMeta={}; (data||[]).forEach(n=>{ noteMeta[n.id]=n; });
  renderMyNotes((data||[]).filter(n=>me&&n.owner_id===me.id));
}
function renderMyNotes(mine){
  const box=$("myNotes"); box.textContent="";
  if(!mine.length){ box.appendChild(el("p","hint","(작성한 노트가 없습니다)")); return; }
  mine.forEach(n=>{
    const card=el("div","note");
    card.appendChild(el("span","id","#"+n.id));
    card.appendChild(el("span","t",n.title));
    card.appendChild(el("span",n.is_private?"badge priv":"badge",n.is_private?"🔒 비공개":"공개"));
    card.onclick=()=>openNote(n.id);
    box.appendChild(card);
  });
}

async function openNote(id){
  id=parseInt(id,10); if(!id)return;
  const d=$("detail"); d.style.display="block"; d.textContent="";
  d.appendChild(el("div","path","GET /notes/"+id));
  const {ok,status,data}=await req("/notes/"+id,{headers:authHeaders()});
  if(!ok){ d.appendChild(el("div","hint","🚫 열람 실패 (HTTP "+status+")"+(status===403?" — 당신 소유가 아닙니다.":status===404?" — 그런 노트가 없습니다.":""))); return; }
  d.appendChild(el("strong",null,data.title||("노트 #"+id)));
  d.appendChild(el("div","body",data.body!=null?data.body:"(본문 없음)"));
  const meta=noteMeta[id];
  if(me && meta && meta.owner_id!==me.id){
    // 내 것이 아닌 노트의 본문이 소유권 검증 없이 열렸다 = IDOR 를 스스로 발견한 것.
    d.appendChild(el("div","idor","⚠️ 이 노트(owner #"+meta.owner_id+")는 당신 소유가 아닙니다. 소유권 검증 없이 본문이 열렸습니다 — IDOR."));
  }
}
$("openBtn").onclick=()=>openNote($("openId").value);
$("openId").addEventListener("keydown",e=>{if(e.key==="Enter")openNote($("openId").value);});

// 초기화: 저장된 토큰이 있으면 로그인 상태 복원(/me 로 검증).
(async()=>{
  if(!token){ setAuthUI(); return; }
  const who=await req("/me",{headers:authHeaders()});
  if(who.ok){ me=who.data; setAuthUI(); loadMyNotes(); } else { logout(); }
})();
</script>
</body></html>"""


@router.get("/", response_class=HTMLResponse)
def index() -> str:
    return _PAGE
