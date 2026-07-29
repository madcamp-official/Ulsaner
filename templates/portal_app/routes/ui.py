"""학생이 실제로 '써보는' 프론트엔드 — 계정 포털. JSON API 를 그대로 호출.

취약 핸들러(db.py 의 verify_token)는 건드리지 않는다. 이 파일은 슬롯 대상이 아니다.

JWT 위조 흐름(단계별 고민):
  1. guest 로 로그인 → JWT 토큰을 받는다. "이게 뭐지?" → JWT.
  2. 디코드 → payload 에 role:"user". 관리자 패널(/admin/flag)은 role:"admin" 을 요구.
  3. role 을 admin 으로 바꾸고 싶은데 서명이 걸려 있다 → "서버가 서명을 검증하나?"
  4. 서명을 아무 값으로 바꾼(또는 재인코딩한) 토큰을 넣어보면 통과 → role:"admin" 위조.
  5. 위조 토큰으로 관리자 패널 → flag.
"""

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter()

_PAGE = """<!doctype html>
<html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Portal — 계정 포털</title>
<style>
  :root{--bg:#f6f7f9;--card:#fff;--line:#e3e6ea;--ink:#1f2328;--muted:#6b7280;--brand:#1f6feb;--danger:#c0392b;--ok:#0f7b6c}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Noto Sans KR",sans-serif}
  header{background:var(--card);border-bottom:1px solid var(--line);padding:14px 20px;display:flex;align-items:center;gap:12px}
  header .logo{font-weight:800;font-size:18px}
  header .sp{margin-left:auto}
  main{max-width:760px;margin:0 auto;padding:22px 20px 60px}
  .panel{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin-bottom:20px}
  h2{font-size:13px;letter-spacing:.04em;text-transform:uppercase;color:var(--muted);margin:0 0 12px}
  input,button,textarea{font:inherit}
  input[type=text],textarea{width:100%;padding:9px 12px;border:1px solid var(--line);border-radius:8px;background:#fff}
  textarea{font:12px/1.5 ui-monospace,Menlo,monospace;min-height:70px;word-break:break-all}
  .row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
  button{cursor:pointer;border:1px solid var(--line);background:#fff;border-radius:8px;padding:9px 14px;font-weight:600}
  button.primary{background:var(--brand);border-color:var(--brand);color:#fff}
  .hint{color:var(--muted);font-size:13px;margin:6px 0 0}
  .out{white-space:pre-wrap;word-break:break-word;border-radius:8px;padding:12px 14px;margin-top:10px;display:none;font:12px/1.5 ui-monospace,Menlo,monospace}
  .out.ok{background:#f0fdf4;border:1px solid #bbf7d0;color:var(--ok)}
  .out.err{background:#fff5f5;border:1px solid #fed7d7;color:var(--danger)}
  .flag{margin-top:10px;padding:12px 14px;background:#eff6ff;border:1px solid #bfdbfe;border-radius:8px;font-weight:700}
</style></head>
<body>
<header>
  <span class="logo">🔐 Portal</span>
  <span class="small" id="who" style="font-size:12px;color:var(--muted)">비로그인</span>
  <span class="sp"></span>
  <button id="logout" style="display:none">로그아웃</button>
</header>
<main>

  <div class="panel" id="loginPanel">
    <h2>로그인</h2>
    <p class="hint">데모 계정으로 로그인합니다.</p>
    <div class="row">
      <input type="text" id="username" value="guest" style="max-width:200px">
      <button class="primary" id="loginBtn">로그인</button>
    </div>
    <p class="hint" id="loginErr" style="color:var(--danger);display:none"></p>
  </div>

  <div class="panel" id="sessionPanel" style="display:none">
    <h2>내 세션 토큰</h2>
    <textarea id="token" spellcheck="false"></textarea>
    <div class="row" style="margin-top:8px">
      <button id="decodeBtn">토큰 디코드</button>
      <button id="meBtn">내 정보 (/me)</button>
      <button class="primary" id="adminBtn">관리자 패널 열기 (/admin)</button>
    </div>
    <div class="out" id="out"></div>
  </div>

</main>
<script>
"use strict";
const $=id=>document.getElementById(id);
const KEY="pt_token";
let loggedIn=false;

function el(tag,cls,txt){ const e=document.createElement(tag); if(cls)e.className=cls; if(txt!=null)e.textContent=txt; return e; }
async function req(path,opts){
  const res=await fetch(path,opts); const raw=await res.text();
  let data=null; try{data=JSON.parse(raw);}catch(e){}
  return {ok:res.ok,status:res.status,data,raw};
}
function b64urlDecode(s){ try{ return decodeURIComponent(escape(atob(s.replace(/-/g,'+').replace(/_/g,'/') + '==='.slice((s.length+3)%4)))); }catch(e){ return "(디코드 실패)"; } }

function setUI(){
  $("who").textContent=loggedIn?"로그인됨":"비로그인";
  $("logout").style.display=loggedIn?"":"none";
  $("loginPanel").style.display=loggedIn?"none":"";
  $("sessionPanel").style.display=loggedIn?"":"none";
}
async function login(){
  const u=$("username").value.trim();
  const {ok,status,data}=await req("/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:u})});
  if(!ok){ $("loginErr").style.display="block"; $("loginErr").textContent="로그인 실패 (HTTP "+status+")"; return; }
  localStorage.setItem(KEY,data.token); $("token").value=data.token; $("loginErr").style.display="none"; loggedIn=true; setUI();
}
function logout(){ loggedIn=false; localStorage.removeItem(KEY); setUI(); }
$("loginBtn").onclick=login;
$("logout").onclick=logout;

$("decodeBtn").onclick=()=>{
  const out=$("out"); out.style.display="block"; out.className="out";
  const parts=$("token").value.trim().split(".");
  if(parts.length!==3){ out.className="out err"; out.textContent="JWT 형식이 아닙니다 (header.payload.signature)"; return; }
  out.textContent="header:  "+b64urlDecode(parts[0])+"\\npayload: "+b64urlDecode(parts[1])+"\\nsignature: "+parts[2];
};
async function callAuthed(path){
  const out=$("out"); out.style.display="block"; out.className="out"; out.textContent="요청 중…";
  const {ok,status,data,raw}=await req(path,{headers:{Authorization:"Bearer "+$("token").value.trim()}});
  if(!ok){ out.className="out err"; out.textContent="HTTP "+status+"\\n"+raw; return null; }
  return data;
}
$("meBtn").onclick=async()=>{ const d=await callAuthed("/me"); if(d){ $("out").className="out ok"; $("out").textContent=JSON.stringify(d); } };
$("adminBtn").onclick=async()=>{
  const d=await callAuthed("/admin/flag");
  if(d){ const out=$("out"); out.className="out ok"; out.textContent="관리자 패널 접근 성공"; out.appendChild(el("div","flag","🚩 "+(d.flag||JSON.stringify(d)))); }
};

// 초기화: 저장된 토큰이 있으면 세션 복원.
(() => { const t=localStorage.getItem(KEY); if(t){ loggedIn=true; setUI(); $("token").value=t; } else setUI(); })();
</script>
</body></html>"""


@router.get("/", response_class=HTMLResponse)
def index() -> str:
    return _PAGE
