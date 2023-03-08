// popup.js

const NAL_DOMAIN = 'fn-share.github.io';

var last_nal_reply = '';

window.addEventListener('message', function(ev) {
  if (ev.data.slice(0,10) == 'CHAN_INFO:') {
    last_nal_reply = ev.data.slice(10);
  }
});

window.addEventListener('load', function(ev) {

function requestNAL(urlArgs, callback) {
  let loc = 'https://' + NAL_DOMAIN + '/account/api/online/' + urlArgs;
  let frmNode = document.createElement('iframe');
  frmNode.setAttribute('style','display:none');
  frmNode.setAttribute('src',loc);
  
  last_nal_reply = '';
  document.body.appendChild(frmNode);
  
  let counter = 0;
  let tid = setInterval( () => {
    counter += 1;
    if (last_nal_reply || counter > 30) {  // max wait 9 seconds
      clearInterval(tid);
      frmNode.remove();
      callback(last_nal_reply);
    }
  }, 300);
}

let passNode = document.querySelector('#pass-word');

let currServerNonce = null;
let currSignHost = ''
let currSignRealm = '';

passNode.addEventListener('keypress', function(ev) {
  if (ev.keyCode != 13) return;
  if (!currServerNonce || currServerNonce.length != 16) return;
  if (!currSignHost || !currSignRealm) return;
  
  // step 1: get hex password string
  let psw = passNode.value;
  if (!psw) return;
  psw = (new TextEncoder('utf-8')).encode(psw);
  
  let hexPsw = '';
  for (let i=0; i < psw.length; i++) {
    let j = psw[i] ^ currServerNonce[i%16];
    hexPsw += ('0' + j.toString(16)).slice(-2);
  }
  
  // step 2: hint waiting
  passNode.value = '';
  passNode.setAttribute('placeholder','等待中 ...');
  
  // step 3: post host,realm,psw
  let urlArgs = 'pass_it?host='+encodeURIComponent(currSignHost)+'&realm='+encodeURIComponent(currSignRealm)+'&psw='+hexPsw;
  requestNAL(urlArgs, res => {
    if (res === 'OK') {
      passNode.value = '';
      passNode.setAttribute('placeholder','授权成功');
      passNode.disabled = true;
      setTimeout(() => window.close(),1200);
    }
    else if (res === 'WAIT_PASS') {
      passNode.value = '';
      passNode.setAttribute('placeholder','密码错误，请再试');
    }
    else alert('系统报错：' + res);
  });
},false);

chrome.tabs.query({active:true,currentWindow:true}, function(tabs) {
  let tab = tabs[0];
  if (!tab) return;
  
  let hostLnk = document.createElement('a');
  hostLnk.setAttribute('href',tab.url);
  
  chrome.tabs.sendMessage(tab.id,{cmd:'nal_sign_what'}, res => {
    if (!res) {
      document.querySelector('#no-pass').style.display = 'block';
      document.querySelector('#wait-pass').style.display = 'none';
      return;
    }
    
    requestNAL('pass_nonce?'+makeNone(16), serv_nonce => {
      currServerNonce = arrayFromHex(serv_nonce);
      currSignHost = hostLnk.host;
      currSignRealm = res;
      
      document.querySelector('#host-desc span').innerHTML = currSignHost;
      document.querySelector('#realm-desc code').innerHTML = res === '@'? 'pass': res;
      passNode.focus();
    });
  });
  
  function makeNone(num) {
    let ret = ''
    for (let i = 0; i < num; i++) {
      let j = Math.floor(Math.random() * 256);  // 0 ~ 255
      ret += ('0' + j.toString(16)).slice(-2);
    }
    return ret;
  }
  
  function arrayFromHex(s) {
    let num = Math.floor(s.length/2);
    let b = new Uint8Array(num);
    for (let i = 0; i < num; i++) {
      let off = i + i;
      b[i] = parseInt(s.slice(off,off+2),16);
    }
    return b;
  }
});

},false);