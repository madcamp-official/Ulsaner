"""학생용 프론트엔드 — 계정 관리 포털. JSON API 를 그대로 호출.

취약 핸들러(db._make_reset_token)는 건드리지 않는다. 다단계 계정 탈취 추리 체인:
  1. 사용자 목록에서 admin 확인.
  2. guest 로 로그인 → 내 계정 재설정 요청 → 메일함에서 토큰 + salt 관찰.
  3. 토큰 = md5(username + salt) 임을 내 데이터로 역추론·검증.
  4. md5("admin" + salt) 계산 → 관리자 재설정 토큰 위조.
  5. 관리자 비번 재설정 → 관리자 로그인 → flag.
"""

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter()

_PAGE = """<!doctype html>
<html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Accounts — 계정 포털</title>
<style>
  :root{--bg:#f6f7f9;--card:#fff;--line:#e3e6ea;--ink:#1f2328;--muted:#6b7280;--brand:#334155;--danger:#c0392b;--ok:#0f7b6c}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Noto Sans KR",sans-serif}
  header{background:var(--card);border-bottom:1px solid var(--line);padding:14px 20px;display:flex;align-items:center;gap:12px}
  header .logo{font-weight:800;font-size:18px}
  header .sp{margin-left:auto}
  main{max-width:820px;margin:0 auto;padding:22px 20px 60px}
  .panel{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 18px;margin-bottom:16px}
  h2{font-size:13px;letter-spacing:.04em;text-transform:uppercase;color:var(--muted);margin:0 0 10px}
  input,button{font:inherit}
  input{padding:8px 11px;border:1px solid var(--line);border-radius:8px;background:#fff}
  .row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
  button{cursor:pointer;border:1px solid var(--line);background:#fff;border-radius:8px;padding:8px 13px;font-weight:600}
  button.primary{background:var(--brand);border-color:var(--brand);color:#fff}
  .hint{color:var(--muted);font-size:12.5px;margin:6px 0 0}
  .out{white-space:pre-wrap;word-break:break-word;background:#0f172a;color:#e2e8f0;border-radius:8px;padding:12px 14px;font:12px/1.6 ui-monospace,Menlo,monospace;margin-top:12px;display:none}
  .flag{margin-top:10px;padding:12px 14px;background:#ecfdf5;border:1px solid #a7f3d0;border-radius:8px;font-weight:700;color:var(--ok)}
</style></head>
<body>
<header>
  <span class="logo">👤 Accounts</span>
  <span class="small" id="who" style="font-size:12px;color:var(--muted)">비로그인</span>
  <span class="sp"></span>
  <button id="logout" style="display:none">로그아웃</button>
</header>
<main>

  <div class="panel">
    <h2>로그인</h2>
    <div class="row">
      <input id="lu" placeholder="username" style="max-width:160px">
      <input id="lp" type="password" placeholder="password" style="max-width:160px">
      <button class="primary" id="loginBtn">로그인</button>
    </div>
    <p class="hint" id="loginErr" style="color:var(--danger);display:none"></p>
  </div>

  <div class="panel">
    <h2>사용자 목록</h2>
    <button id="usersBtn">GET /users</button>
  </div>

  <div class="panel">
    <h2>비밀번호 재설정</h2>
    <div class="row">
      <input id="rr" placeholder="username" style="max-width:160px">
      <button id="resetReqBtn">재설정 메일 요청</button>
      <button id="inboxBtn">내 메일함 열기</button>
    </div>
    <p class="hint">재설정 메일은 해당 계정의 메일함으로만 전송됩니다. (내 메일함은 로그인 후 열람)</p>
    <div class="row" style="margin-top:10px">
      <input id="cu" placeholder="username" style="max-width:140px">
      <input id="ct" placeholder="reset token" style="max-width:240px">
      <input id="cp" placeholder="new password" style="max-width:150px">
      <button id="confirmBtn">재설정 확정</button>
    </div>
  </div>

  <div class="panel">
    <h2>관리자 패널</h2>
    <button class="primary" id="adminBtn">GET /admin/flag</button>
  </div>

  <div class="out" id="out"></div>
</main>
<script>
"use strict";
const $=id=>document.getElementById(id);
const KEY="ac_token";
let token=localStorage.getItem(KEY)||"";

function authH(){ return token?{Authorization:"Bearer "+token}:{}; }
function el(t,c,x){ const e=document.createElement(t); if(c)e.className=c; if(x!=null)e.textContent=x; return e; }
async function req(path,opts){ const r=await fetch(path,opts); const raw=await r.text(); let d=null; try{d=JSON.parse(raw);}catch(e){} return {ok:r.ok,status:r.status,data:d,raw}; }
function show(obj,cls){ const o=$("out"); o.style.display="block"; o.className="out"; o.textContent=typeof obj==="string"?obj:JSON.stringify(obj,null,2); if(cls==="flag"){} return o; }
function setWho(){ $("who").textContent=token?"세션 있음":"비로그인"; $("logout").style.display=token?"":"none"; }

$("loginBtn").onclick=async()=>{
  const {ok,status,data}=await req("/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:$("lu").value,password:$("lp").value})});
  if(!ok){ $("loginErr").style.display="block"; $("loginErr").textContent="로그인 실패 (HTTP "+status+")"; return; }
  token=data.token; localStorage.setItem(KEY,token); $("loginErr").style.display="none"; setWho(); show("로그인 성공: "+$("lu").value);
};
$("logout").onclick=()=>{ token=""; localStorage.removeItem(KEY); setWho(); show("로그아웃됨"); };
$("usersBtn").onclick=async()=>{ const {data}=await req("/users"); show(data); };
$("resetReqBtn").onclick=async()=>{ const {data}=await req("/reset/request",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:$("rr").value})}); show("재설정 요청 결과: "+JSON.stringify(data)); };
$("inboxBtn").onclick=async()=>{ const {ok,status,data}=await req("/inbox",{headers:authH()}); show(ok?data:"HTTP "+status+" (로그인 필요)"); };
$("confirmBtn").onclick=async()=>{ const {ok,status,data}=await req("/reset/confirm",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:$("cu").value,token:$("ct").value,new_password:$("cp").value})}); show(ok?("재설정 성공: "+JSON.stringify(data)):"HTTP "+status+" — 토큰이 맞지 않습니다"); };
$("adminBtn").onclick=async()=>{
  const {ok,status,data}=await req("/admin/flag",{headers:authH()});
  if(!ok){ show("HTTP "+status+" — 관리자만 접근 가능"); return; }
  const o=show("관리자 패널 접근 성공"); o.appendChild(el("div","flag","🚩 "+(data.flag||JSON.stringify(data))));
};

setWho();
</script>
</body></html>"""


@router.get("/", response_class=HTMLResponse)
def index() -> str:
    return _PAGE
