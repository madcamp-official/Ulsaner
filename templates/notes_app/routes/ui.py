"""학생이 실제로 '써보는' 프론트엔드 (실전성). JSON API를 그대로 호출하는 단일 페이지.

취약 핸들러(routes/notes.py·search.py·db.py)는 건드리지 않는다 — 이 파일은 슬롯 대상이
아니며, 브라우저가 학생 권한으로 호출할 수 있는 API만 부른다(취약점 표면을 그대로 노출할
뿐 새 노출은 없다). 렌더는 전부 textContent 라 프론트 자체가 XSS를 더하지 않는다.

흐름:
  - 검색(공개) → GET /notes/search : SQLi 표면. 깨지면 원 오류를 그대로 보여줘 '탐침 → 악용'.
  - 로그인(선택, IDOR용) → 과제에 나온 토큰을 넣으면 워크스페이스 피드를 본다.
  - 피드 → GET /notes : 남의 비공개 노트도 '목록'에 보인다(메타데이터). 클릭하면
    GET /notes/{id} — 취약하면 본문이 열리고(=IDOR 발견), 고쳐졌으면 403.
"""

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter()

_PAGE = """<!doctype html>
<html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Notebook — 워크스페이스 노트</title>
<style>
  :root{--bg:#f6f7f9;--card:#fff;--line:#e3e6ea;--ink:#1f2328;--muted:#6b7280;--brand:#2f6feb;--danger:#c0392b}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Noto Sans KR",sans-serif}
  header{background:var(--card);border-bottom:1px solid var(--line);padding:14px 20px;display:flex;align-items:center;gap:12px}
  header .logo{font-weight:800;font-size:18px}
  header .sp{margin-left:auto}
  main{max-width:860px;margin:0 auto;padding:22px 20px 60px}
  .panel{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin-bottom:20px}
  h2{font-size:13px;letter-spacing:.04em;text-transform:uppercase;color:var(--muted);margin:0 0 12px}
  input,button{font:inherit}
  input[type=text],input[type=password]{width:100%;padding:9px 12px;border:1px solid var(--line);border-radius:8px;background:#fff}
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
  details summary{cursor:pointer;color:var(--muted);font-size:13px;margin-top:8px}
  .small{font-size:12px;color:var(--muted)}
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
    <h2>워크스페이스 노트</h2>
    <div id="loginBox">
      <p class="hint">워크스페이스 노트를 보려면 액세스 토큰으로 로그인하세요.</p>
      <div class="row">
        <input type="password" id="token" placeholder="액세스 토큰 (예: Bearer token-xxxx 의 token-xxxx)" autocomplete="off" spellcheck="false">
        <button class="primary" id="loginBtn">로그인</button>
      </div>
      <p class="hint" id="loginErr" style="color:var(--danger);display:none"></p>
    </div>
    <div id="feed" style="display:none"></div>
    <div class="detail" id="detail"></div>
  </div>

</main>
<script>
"use strict";
const $=id=>document.getElementById(id);
const KEY="nb_token";
let token=localStorage.getItem(KEY)||"";

function authHeaders(){ return token?{Authorization:"Bearer "+token}:{}; }
function el(tag,cls,txt){ const e=document.createElement(tag); if(cls)e.className=cls; if(txt!=null)e.textContent=txt; return e; }

async function req(path,opts){
  const res=await fetch(path,opts);
  let data=null,raw=""; raw=await res.text();
  try{data=JSON.parse(raw);}catch(e){}
  return {ok:res.ok,status:res.status,data,raw};
}

// ---- 검색(공개) ----
async function search(path){
  const out=$("searchOut"); out.style.display="block"; out.className="out"; out.textContent="검색 중…";
  const {ok,status,data,raw}=await req(path);
  if(!ok){ out.className="out err"; out.textContent="HTTP "+status+"\\n"+raw; return; }  // 깨진 쿼리 원문 노출 = SQLi 탐침 신호
  const rows=(data&&data.results)||[];
  out.className="out";
  if(!rows.length){ out.textContent="(결과 없음)"; return; }
  out.textContent=rows.map(r=>"#"+r.id+"  "+r.title).join("\\n");
}
$("searchBtn").onclick=()=>search("/notes/search?q="+encodeURIComponent($("q").value));
$("q").addEventListener("keydown",e=>{if(e.key==="Enter")$("searchBtn").click();});
$("advBtn").onclick=()=>search("/notes/search/advanced?q="+encodeURIComponent($("aq").value)+"&exclude="+encodeURIComponent($("aexclude").value));

// ---- 로그인 / 피드 (IDOR) ----
function setAuthUI(){
  const on=!!token;
  $("who").textContent=on?"로그인됨":"비로그인";
  $("logout").style.display=on?"":"none";
  $("loginBox").style.display=on?"none":"";
  $("feed").style.display=on?"":"none";
}
async function login(){
  const raw=$("token").value.trim().replace(/^Bearer\\s+/i,"");
  if(!raw)return;
  token=raw;
  const {ok,status}=await req("/notes",{headers:authHeaders()});
  if(!ok){ $("loginErr").style.display="block"; $("loginErr").textContent="로그인 실패 (HTTP "+status+") — 토큰을 확인하세요."; token=""; return; }
  localStorage.setItem(KEY,token); $("loginErr").style.display="none"; setAuthUI(); loadFeed();
}
function logout(){ token=""; localStorage.removeItem(KEY); $("detail").style.display="none"; setAuthUI(); }
$("loginBtn").onclick=login;
$("token").addEventListener("keydown",e=>{if(e.key==="Enter")login();});
$("logout").onclick=logout;

async function loadFeed(){
  const feed=$("feed"); feed.textContent="";
  const {ok,data}=await req("/notes",{headers:authHeaders()});
  if(!ok){ logout(); return; }
  (data||[]).forEach(n=>{
    const card=el("div","note");
    card.appendChild(el("span","id","#"+n.id));
    card.appendChild(el("span","t",n.title));
    card.appendChild(el("span","badge owner-"+n.owner_id,"owner #"+n.owner_id));
    card.appendChild(el("span",n.is_private?"badge priv":"badge",n.is_private?"🔒 비공개":"공개"));
    card.onclick=()=>openNote(n.id);
    feed.appendChild(card);
  });
}
async function openNote(id){
  const d=$("detail"); d.style.display="block"; d.textContent="";
  d.appendChild(el("div","path","GET /notes/"+id));
  const {ok,status,data}=await req("/notes/"+id,{headers:authHeaders()});
  if(!ok){ d.appendChild(el("div","hint","🚫 열람 실패 (HTTP "+status+")"+(status===403?" — 당신 소유가 아닙니다.":""))); return; }
  d.appendChild(el("div",null,"")).appendChild(el("strong",null,data.title||("노트 #"+id)));
  d.appendChild(el("div","body",data.body!=null?data.body:"(본문 없음)"));
}

setAuthUI();
if(token) loadFeed();
</script>
</body></html>"""


@router.get("/", response_class=HTMLResponse)
def index() -> str:
    return _PAGE
