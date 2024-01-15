// popup.js

window.addEventListener('load', ev => {

let currServerNonce = null;
let currSignHost = ''
let currSignRealm = '';

const passNode = document.querySelector('#pass-word');

passNode.addEventListener('keypress', ev => {
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
  let msg = {cmd:'pass_it',param:[currSignHost,currSignRealm,hexPsw]};
  chrome.runtime.sendMessage(JSON.stringify(msg), res => {
    res = JSON.parse(res);
    if (res && res.result === 'OK') {
      passNode.value = '';
      passNode.setAttribute('placeholder','授权成功');
      passNode.disabled = true;
      setTimeout(() => window.close(),1200);
    }
    else if (res && res.result === 'WAIT_PASS') {
      passNode.value = '';
      passNode.setAttribute('placeholder','密码错误，请再试');
    }
    else alert('系统报错：' + res.result);
  });
},false);

function nalSignWhat() {
  let lastSign  = parseInt(document.body.getAttribute('nal-last-sign') || '0');
  let lastRealm = document.body.getAttribute('nal-last-realm') || '';
  
  if (Math.floor((new Date()).getTime() / 1000) - lastSign > 60)
    lastRealm = ''; // clear realm when 60 seconds later
  return lastRealm;
}

chrome.tabs.query({active:true,currentWindow:true}, function(tabs) {
  let tab = tabs[0];
  if (!tab) return;
  
  let hostLnk = document.createElement('a');
  hostLnk.setAttribute('href',tab.url);
  
  chrome.scripting.executeScript({target:{tabId:tab.id},function:nalSignWhat}).then( results => {
    let res = null;
    if (results && results.length)
      res = results[0].result;
    if (typeof res != 'string' || !res) {
      document.querySelector('#no-pass').style.display = 'block';
      document.querySelector('#wait-pass').style.display = 'none';
      return;
    }
    
    let msg = {cmd:'pass_nonce',param:[makeNonce(16)]};
    chrome.runtime.sendMessage(JSON.stringify(msg), res2 => {
      res2 = JSON.parse(res2);
      currServerNonce = arrayFromHex(res2.result);
      currSignHost = hostLnk.host;
      currSignRealm = res;
      
      document.querySelector('#host-desc span').innerHTML = currSignHost;
      document.querySelector('#realm-desc code').innerHTML = currSignRealm === '@'? 'pass': currSignRealm;
      passNode.focus();  // wait inputting password
    });
  });
  
  function makeNonce(num) {
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
