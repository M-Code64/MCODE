<script>
// ================= ENTRY LOCK =================
const ENTRY_PASSWORD = "MC64";
const entryOverlay = document.getElementById("entryOverlay");
const entryError = document.getElementById("entryError");

function checkEntry(){
  if(document.getElementById("sitePassword").value === ENTRY_PASSWORD){
    localStorage.setItem("entryOk","1");
    entryOverlay.style.display="none";
  } else { entryError.textContent="Wrong entry password!"; }
}

window.onload=()=>{ 
  if(localStorage.getItem("entryOk")) entryOverlay.style.display="none"; 
};

// ================= UI =================
function togglePass(){
  const p=document.getElementById("password");
  p.type=p.type==="password"?"text":"password";
}

const input=document.getElementById("input");
const output=document.getElementById("output");
const errorMsg=document.getElementById("errorMsg");

// ================= CRYPTO =================
const SIGNATURE="MCODEv2";
const ITER=300000;
const enc=new TextEncoder();
const dec=new TextDecoder();

const b64e=u8=>btoa(String.fromCharCode(...u8));
const b64d=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));

function pack(...arrs){
  let len=arrs.reduce((a,b)=>a+b.length,0), o=0, out=new Uint8Array(len);
  for(const a of arrs){ out.set(a,o); o+=a.length; }
  return out;
}

async function deriveKey(p,salt){
  const base=await crypto.subtle.importKey(
    "raw", enc.encode(p+SIGNATURE), "PBKDF2", false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {name:"PBKDF2", salt, iterations:ITER, hash:"SHA-256"},
    base, {name:"AES-GCM", length:256}, false, ["encrypt","decrypt"]
  );
}

// ================= SHORT B64URL =================
const M2="M2";
const b64url=b64=>b64.replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const b64urld=b64=>{
  let s=b64.replace(/-/g,'+').replace(/_/g,'/');
  while(s.length%4) s+='=';
  return b64d(s);
}

// ================= ENCRYPT / DECRYPT =================
async function encrypt(){
  errorMsg.textContent="";
  if(!password.value){ errorMsg.textContent="Password required"; return; }

  const salt=crypto.getRandomValues(new Uint8Array(16));
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const key=await deriveKey(password.value,salt);

  const data=enc.encode(SIGNATURE+"::"+input.value);
  const cipher=await crypto.subtle.encrypt({name:"AES-GCM",iv},key,data);

  const full=b64e(pack(salt,iv,new Uint8Array(cipher)));
  output.value=M2+"."+b64url(full);
  output.style.color="#0ff";
}

async function decrypt(){
  errorMsg.textContent="";
  if(!password.value){ errorMsg.textContent="Password required"; return; }
  if(!input.value){ output.value=""; return; }

  try{
    const str=input.value.trim();
    if(!str.startsWith(M2+'.')) throw "INVALID DATA";

    const raw=b64urld(str.slice(M2.length+1));

    if(raw.length>32){ // AES-GCM (salt+iv+cipher)
      const salt=raw.slice(0,16);
      const iv=raw.slice(16,28);
      const data=raw.slice(28);

      const key=await deriveKey(password.value,salt);
      const plain=await crypto.subtle.decrypt({name:"AES-GCM",iv},key,data);
      const txt=dec.decode(plain);

      if(!txt.startsWith(SIGNATURE+"::")) throw 0;
      output.value=txt.slice(SIGNATURE.length+2);
      output.style.color="#0ff";

    } else { // short M2 encoded
      output.value=dec.decode(raw);
      output.style.color="#0ff";
    }

  }catch{
    output.value="❌ WRONG PASSWORD OR INVALID DATA";
    output.style.color="#ff5555";
  }
}

// ================= SHORT ENCODE/DECODE =================
function encodeShort(){
  errorMsg.textContent="";
  if(!input.value){ errorMsg.textContent="Input required"; return; }
  const data=enc.encode(input.value);
  output.value=M2+"."+b64url(b64e(data));
  output.style.color="#0ff";
}

function decodeShort(){
  errorMsg.textContent="";
  if(!input.value){ errorMsg.textContent="Input required"; return; }
  try{
    const str=input.value.trim();
    if(!str.startsWith(M2+'.')) throw 0;
    const raw=b64urld(str.slice(M2.length+1));
    output.value=dec.decode(raw);
    output.style.color="#0ff";
  }catch{
    output.value="❌ INVALID DATA";
    output.style.color="#ff5555";
  }
}
</script>

