importScripts('/account/scripts/workbox-v6.5.4/workbox-sw.js');
workbox.setConfig({ // debug:true,
  modulePathPrefix:'/account/scripts/workbox-v6.5.4/' });

importScripts('/account/scripts/idb-v7.1.0/umd.js');
importScripts('/account/api/0/nbc_base-0.1.min.js');

const wallet_db = idb.openDB( 'wallet-db',1, {
  upgrade(db) {
    if (!db.objectStoreNames.contains('config')) {
      let store = db.createObjectStore('config',{keyPath:'name'});
      store.createIndex('magic_tm','magic_tm');
    }
    if (!db.objectStoreNames.contains('wait_sign')) {
      let store = db.createObjectStore('wait_sign',{keyPath:'host'});
      store.createIndex('request_tm','request_tm');
    }
    if (!db.objectStoreNames.contains('sign_history')) {
      let store = db.createObjectStore('sign_history',{keyPath:'id',autoIncrement:true});
      store.createIndex('sign_tm','sign_tm');
    }
    if (!db.objectStoreNames.contains('recent_cards')) {
      let store = db.createObjectStore('recent_cards',{keyPath:['host','flag','role','child']});
      store.createIndex('host_expired',['host','expired']);
      store.createIndex('expired','expired');
    }
  },
});

const ECC = require('tiny-secp256k1');
const ECDH = require('create-ecdh')('secp256k1');
const CryptoJS = require('crypto-js');
const CreateHash = require('create-hash');
const Buffer = require('safe-buffer').Buffer;
const base36 = require('base-x')('0123456789abcdefghijklmnopqrstuvwxyz');
const bip32 = require('bip32');
const bip66 = require('bip66');

const ZERO = Buffer.alloc(1,0);

const DEFAULT_REAL_SERVER = 'real.fn-share.com';
const DEFAULT_REAL_MANAGER = { type:'',
  'rsp_admin_pubkey':'028729396e71748b2cb56425335618218bc850a170da1adf59355278836b6b2624',
  'csp_plt_pubkey':'03d72fa51f87d007a9c98e858bb057cb4e280ee1c8d97516af96ec1c9e13d63c36',
  'csp_pdt_pubkey':'02ffef6766b43225e273a5da598037c1787b3b9c1043e99b27a780d06d0ae367bf',
  'csp_selector': 'www.fn-share.com/crypto_host',
};

function wrapCryptoBuf(msg) {
  if (msg.words instanceof Array)  // msg is instance of CryptoJS.lib.WordArray
    return msg;
  else if (msg.buffer instanceof ArrayBuffer)  // msg is instance of Buffer
    return CryptoJS.lib.WordArray.create(msg);
  else return CryptoJS.enc.Utf8.parse(msg);    // assume msg is utf-8 string
}

function AesCbcEncrypt(prv, iv, msg) {
  prv = wrapCryptoBuf(prv);
  iv = wrapCryptoBuf(iv);
  msg = wrapCryptoBuf(msg);
  
  let encrypted = CryptoJS.AES.encrypt(msg, prv, {
    iv: iv,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.ZeroPadding
  });
  // encrypted.toString() is base64-string, encrypted.ciphertext.toString() is hex-string
  return encrypted.ciphertext;  // return CryptoJS.lib.WordArray
}

function AesCbcDecrypt(prv, iv, msg, zeroPad) { // msg must be base64 string, default NoPadding
  prv = wrapCryptoBuf(prv);
  iv = wrapCryptoBuf(iv);
  
  return CryptoJS.AES.decrypt(msg, prv, {
    iv: iv,
    mode: CryptoJS.mode.CBC,
    padding: typeof zeroPad == 'number'? CryptoJS.pad.ZeroPadding: CryptoJS.pad.NoPadding
  });  // return CryptoJS.lib.WordArray
}

function AesCtrEncrypt(prv, iv, msg) {
  prv = wrapCryptoBuf(prv);
  iv = wrapCryptoBuf(iv);
  msg = wrapCryptoBuf(msg);
  
  let encrypted = CryptoJS.AES.encrypt(msg, prv, {
    iv: iv,
    mode: CryptoJS.mode.CTR,
    padding: CryptoJS.pad.ZeroPadding
  });
  return encrypted.ciphertext;  // return CryptoJS.lib.WordArray
}

function AesCtrDecrypt(prv, iv, msg, noPad) { // msg must be base64 string, default ZeroPadding
  prv = wrapCryptoBuf(prv);
  iv = wrapCryptoBuf(iv);
  
  return CryptoJS.AES.decrypt(msg, prv, {
    iv: iv,
    mode: CryptoJS.mode.CTR,
    padding: noPad? CryptoJS.pad.NoPadding: CryptoJS.pad.ZeroPadding
  });  // return CryptoJS.lib.WordArray
}

function encryptMsg(k_iv, msg) { // msg can be: utf-8-string, Buffer, CryptoJS.lib.WordArray
  return AesCbcEncrypt(k_iv.slice(0,16),k_iv.slice(16,32),msg);
}

function decryptMsg(k_iv, msg) { // msg only can be base64
  return AesCbcDecrypt(k_iv.slice(0,16),k_iv.slice(16,32),msg);
}

const NAL_WEBHOST = 'fn-share.github.io';

function generateRand(num) {
  let ret = Buffer.alloc(num,0);
  for (let i=0; i < num; i++) {
    ret[i] = Math.floor(Math.random() * 256);  // 0 ~ 255
  }
  return ret;
}

function parseUrlArg(arg) {
  var d = {}, b = arg.split('&');
  for (var i=0,s; s=b[i]; i++) {
    var b2 = s.split('=');
    var sName = b2[0];
    
    b2.splice(0,1);
    if (b2.length == 0)
      d[sName] = '';
    else d[sName] = decodeURIComponent(b2.join('='));
  }
  return d;
}

workbox.routing.registerRoute(
  new RegExp('^(http|https)://[^/]+/account/api/\\d+[^/]*/.*$'),
  new workbox.strategies.CacheOnly({cacheName:'immutables'}) // CacheOnly is better than CacheFirst
);

workbox.routing.registerRoute(
  new RegExp('^(http|https)://[^/]+/account/api/last/.*$'),
  new workbox.strategies.CacheFirst({cacheName:'immutables'})
);

workbox.routing.registerRoute(
  new RegExp('^(http|https)://[^/]+/account/api/sw-(\\d|\\.)+js$'),
  new workbox.strategies.CacheFirst({cacheName:'immutables'})
);

workbox.routing.registerRoute(
  new RegExp('^(http|https)://([^/]+)/account/api/online/is_ready$'),
  ({url, event, params}) => {
    return new Response(rootBip.hasInit()?'READY':'NONE');
  }
);

//----

async function recycleDataStore() {
  let now = Math.ceil((new Date()).valueOf() / 1000);
  let range = IDBKeyRange.lowerBound(86400-now);  // 1 days ago
  let range2 = IDBKeyRange.lowerBound(5184000-now);  // 60 days ago
  let range3 = IDBKeyRange.lowerBound(31536000-now); // 365 days ago
  
  let db = await wallet_db;
  
  let items = await db.getAllFromIndex('config','magic_tm',range3);
  items.forEach( item => db.delete('config',item.name) );  // not await
  
  items = await db.getAllFromIndex('wait_sign','request_tm',range);
  items.forEach( item => db.delete('wait_sign',item.host) );  // not await
  
  items = await db.getAllFromIndex('sign_history','sign_tm',range2);
  items.forEach( item => db.delete('sign_history',item.id) ); // not await
  
  items = await db.getAllFromIndex('recent_cards','expired',range);
  items.forEach( item => db.delete('recent_cards',[item.host,item.flag,item.child]) ); // not await
}

function _renewCryptoHost(db, accInfo, now) {
  // default fetch timeout is indicated by the browser, chrome is 300s, firefox is 90s
  fetch(REAL_MANAGER.csp_selector).then(res => res.text()).then( res2 => {
    if (res2 && typeof res2 == 'string') {
      accInfo.crypto_host = res2;
      accInfo.crypto_host_tm = now;
      db.put('config',accInfo);
    }
  });
}

async function checkCryptoHost() {
  let db = await wallet_db;
  let accInfo = await db.get('config','account');
  if (accInfo) {
    let now = Math.floor((new Date()).valueOf()/1000);
    if (!accInfo.crypto_host || now - (accInfo.crypto_host_tm||0) > 259200) // need renew, 259200 is 3 days
      _renewCryptoHost(db,accInfo,now);  // no wait
  }
}

workbox.routing.registerRoute(
  new RegExp('^(http|https)://([^/]+)/account/api/online/regist_magic\\?(.*)$'),
  async ({url, event, params}) => {
    let host = event.request.referrer || '';
    host = (host.split('://')[1] || '').split('/')[0];
    // if (host == 'localhost:9000') host = NAL_WEBHOST;  // for NAL debugging
    
    let magic = 0, args = parseUrlArg(params[2]);
    if (typeof args.magic == 'string') magic = parseInt(args.magic);
    magic = magic || 0;
    
    let hostCfg = await (await wallet_db).get('config',host);
    if (!hostCfg) hostCfg = {name:host};
    hostCfg.sw_magic = magic;
    hostCfg.magic_tm = 0-Math.floor((new Date()).valueOf() / 1000);
    await (await wallet_db).put('config', hostCfg);
    
    if (host === NAL_WEBHOST)
      setTimeout(() => recycleDataStore(),3000);
    else setTimeout(() => checkCryptoHost(),3000);
    
    let strategy_ver = hostCfg.strategy?.strategy_ver || 0;
    let storage = hostCfg.storage || null;
    let info = JSON.stringify({strategy_ver,host,storage});
    let ret = `<html><body><script>window.parent.postMessage('CHAN_INFO:${magic}:${info}','*');</script></body></html>`;
    let headers = new Headers([['Content-Type','text/html']]);
    return new Response(ret,{status:200,statusText:'',headers});
  }
);

//----

const REALM_SECRET = '';
const secp256k_order = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');

// 6m, 15m, 30m, 1h, 3h, 8h, 1d, 7d
const session_periods = [360,900,1800,3600,10800,28800,86400,604800];
// 30m, 90m, 5h, 10h, 24h, 3d, 7d, 63d
const refresh_periods = [1800,5400,18000,36000,86400,259200,604800,5443200];  

const URL_SECRET = ((fixed_secret) => {
  let last_secret = generateRand(16);
  
  return {
    setLastNonce(nonce) {
      let nonce2 = Buffer.alloc(16,0); // align to 16 bytes
      for (let i=0; i < 16; i++) {
        nonce2 = nonce[i] || 0;
      }
      last_secret = nonce2;
    },
    
    mixupNonce() {
      let ret = Buffer.alloc(16,0);
      for (let i=0; i < 16; i++) {
        ret[i] = fixed_secret[i] ^ last_secret[i];
      }
      return ret;
    },
    
    decodePsw(psw) {
      let nonce = URL_SECRET.mixupNonce();
      let psw2 = Buffer.alloc(psw.length,0);
      for (let i=0; i < psw.length; i++) {
        psw2[i] = psw[i] ^ nonce[i % 16];
      }
      return psw2.toString('utf-8');
    },
  };
})(generateRand(16));

const _LOWER_CHAR = 'abcdefghijklmnopqrstuvwxyz';
const _UPPER_CHAR = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const _NUMB_CHAR  = '0123456789';

function genRsvdList(rsvd) {
  let s = rsvd.slice(0,5);
  if (s.length < 3) s = ('000' + s).slice(-3);
  let inLen = s.length; // min 3 char, max 5 char
  let tail = inLen == 3? '\x00\x00': (inLen == 4? '\x00': '');
  
  let b = [];
  while (true) {
    let s2 = '';
    for (let i=0; i < inLen; i++) {
      let ch = s[i], ch2 = 'z';
      if (_LOWER_CHAR.indexOf(ch) >= 0)
        ch2 = _LOWER_CHAR[Math.floor(Math.random()*26)];  // _LOWER_CHAR[0~25]
      else if (_UPPER_CHAR.indexOf(ch) >= 0)
        ch2 = _UPPER_CHAR[Math.floor(Math.random()*26)];  // _UPPER_CHAR[0~25]
      else if (_NUMB_CHAR.indexOf(ch) >= 0)
        ch2 = _NUMB_CHAR[Math.floor(Math.random()*10)];   // _NUMB_CHAR[0~9]
      s2 += ch2;
    }
    s2 += tail;
    
    if (b.indexOf(s2) < 0) {
      b.push(s2);
      if (b.length >= 9) break;
    }
  }
  
  let idx = Math.floor(Math.random()*9);
  b[idx] = s + tail;
  return [idx,Buffer.from(b.join(''))];
}

function gen_fix_key(phone, psw) {
  let msg = Buffer.from(REALM_SECRET+':'+phone+':'+psw);
  let ha = CreateHash('sha256').update(msg).digest();
  let n = BigInt('0x' + ha.toString('hex'));
  n = n % secp256k_order;
  if (n === 0n)  // very very seldom, but it could happen
    throw new Error('fatal error, you should choose another password');
  n = n.toString(16);
  if (n.length & 0x01) n = '0' + n;
  n = Buffer.from(n,'hex');
  
  let ret = Buffer.alloc(32,0);
  n.copy(ret,32 - n.length,0);  // copy(targBuffer,targStart,sourStart,sourEnd)
  return ret;
}

/* hash256() can be enhanced by ASIC chip, so we change to wasm VDF
function enhanceFixKey(fixKey) {
  let data = CreateHash('sha256').update(fixKey).digest(); 
  let ha = CreateHash('sha256');
  for (let i=0; i < 1000000; i++) { // less than 1 second mostly
    ha.update(data);
  }
  return ha.digest();
} */

let vdfInstance  = null;
let REAL_MANAGER = null;

function setupRealManagers(info) {
  let tmp = { type:info.type||''};
  tmp.rsp_admin_pubkey = Buffer.from(info.rsp_admin_pubkey,'hex');
  tmp.rsp_admin_fp = ripemdHash(tmp.rsp_admin_pubkey).slice(0,4);
  tmp.csp_plt_pubkey = Buffer.from(info.csp_plt_pubkey,'hex');
  tmp.csp_plt_fp = ripemdHash(tmp.csp_plt_pubkey).slice(0,4);
  tmp.csp_pdt_pubkey = Buffer.from(info.csp_pdt_pubkey,'hex');
  tmp.csp_pdt_fp = ripemdHash(tmp.csp_pdt_pubkey).slice(0,4);
  tmp.csp_selector = 'https://' + info.csp_selector;
  return tmp;
}

setTimeout( async () => {
  let accInfo = await (await wallet_db).get('config','account');
  if (accInfo?.real_manager)
    REAL_MANAGER = setupRealManagers(accInfo.real_manager);
  
  if (location.hostname != 'localhost') {  // no VDF when debugging at localhost
    const createVdf = require('@subspace/vdf').default;
    vdfInstance = await createVdf();
  }
}, 3000);

function enhanceFixKey(fixKey) {
  if (vdfInstance === null) return fixKey;
  
  try {
    // iterations = 4000, intSizeBits = 512, isPietrzak = false
    const proof = vdfInstance.generate(4000,fixKey,512,false); // less than 2 seconds mostly
    return CreateHash('sha256').update(proof).digest();
  }
  catch(e) {
    console.log(e);
    return fixKey;
  }
}

function getAccountRsvd(accInfo) {
  let tmp = accInfo.rsvd_index * 10;
  tmp = Buffer.from(accInfo.rsvd_list.slice(tmp,tmp+10),'hex');
  if (tmp[4] == 0)
    tmp = tmp[3] == 0? tmp.slice(0,3): tmp.slice(0,4);
  return tmp.toString('utf-8');
}

function configCheckBip(psw, accInfo) {
  try {
    let fixKey = gen_fix_key(accInfo.phone,psw);
    let secret = decryptMsg(enhanceFixKey(fixKey),accInfo.hosting_data);
    let fp = parseInt(accInfo.figerprint.slice(0,8),16);
    rootBip.config(Buffer.from(secret.toString(CryptoJS.enc.Hex),'hex'),accInfo,fp);
    
    let bipInfo = rootBip.info();
    if (bipInfo.psw_pubkey && bipInfo.psw_pubkey.slice(0,4) === accInfo.psw_pubkey_head)
      return bipInfo;  // check psw OK
    else {
      rootBip.disableBip();
      return null;
    }
  }
  catch(e) {
    console.log(e);
    rootBip.disableBip();
    return null;
  }
}

function verifyAccoutPass(psw, accInfo) {
  if (!rootBip.hasInit() || !accInfo) return false;
  
  try {
    let fixKey = gen_fix_key(accInfo.phone,psw);
    
    let secret = decryptMsg(enhanceFixKey(fixKey),accInfo.hosting_data);
    secret = Buffer.from(secret.toString(CryptoJS.enc.Hex),'hex');
    let pswAcc = bip32.fromPrivateKey(secret.slice(64,96),secret.slice(96,128));
    pswAcc = pswAcc.derive(0x80000000); // forget original pay account
    
    let bipInfo = rootBip.info();
    if (bipInfo.psw_pubkey === pswAcc.publicKey.toString('hex'))
      return true
    else return false;
  }
  catch(e) {
    console.log(e);
    return false;
  }
}

async function passNalAuth(db, targHost, targRealm) {
  // step 1: get record from wait_sign and config of target host
  let info = await db.get('wait_sign',targHost);
  let cfg2 = await db.get('config',targHost);
  if (info && cfg2) {
    await db.delete('wait_sign',targHost);
    
    let targSegm = info.realm.split('+');
    let targRole = targSegm[0];
    let roleInfo = (cfg2.strategy?.roles || {})[targRole];
    if (!roleInfo)  // double check targRole
      return 'INVALID_ROLE';
    
    if (targRealm && info.realm.indexOf(targRealm) != 0)
      return 'REALM_MISMATCH';
    
    // step 2: check timeout
    let now = Math.floor((new Date()).valueOf() / 1000);
    if (info.request_tm >= 3600-now)  // one hour ago
      return 'TIMEOUT';
    
    // step 3: make signature and save to DB
    let info2 = rootBip.sessionSign(info.child,targHost,info.realm,info.content);
    info.pubkey = info2[0].toString('hex');
    info.signature = info2[1].toString('hex');
    info.sign_tm = 0 - now;
    await db.put('sign_history',info);
    
    // step 4: if is login, save login info to DB
    if (targSegm.length == 2 && targSegm[1] == 'login') {
      let limitSec = (cfg2.strategy.session_limit+1) * refresh_periods[cfg2.strategy.session_type&0x07];
      cfg2.login_role = targRole;
      cfg2.login_child = info.child;  // 'child1,child2,child3' means login by green card, if 'child1' and child1 >=0x80000000 means login by meta passport
      cfg2.login_pubkey = info.pubkey;
      cfg2.login_time = Math.floor((new Date()).valueOf() / 1000);
      cfg2.login_expired = cfg2.login_time + limitSec;
      await db.put('config',cfg2);
    }
  }
  // else, nothing to sign
  
  return 'OK';
}

workbox.routing.registerRoute(   // pass_nonce?hex_nonce16
  new RegExp('^(http|https)://([^/]+)/account/api/online/pass_nonce\\?(.*)$'),
  ({url, event, params}) => {
    let nonce = Buffer.from(params[2],'hex'), nonce2 = Buffer.alloc(16,0);
    for (let i=0; i < 16; i++) { // align to 16 bytes
      nonce2 = nonce[i] || 0;
    }
    URL_SECRET.setLastNonce(Buffer.from(params[2],'hex'));
    
    let ret = URL_SECRET.mixupNonce().toString('hex');
    let headers = new Headers([['Content-Type','text/html']]);
    ret = '<html><body><script>window.parent.postMessage("CHAN_INFO:' + ret + '","*");</script></body></html>';
    return new Response(ret,{status:200,statusText:'',headers});
  }
);

workbox.routing.registerRoute(   // pass_it?host=xx&realm=xx&psw=xx
  new RegExp('^(http|https)://([^/]+)/account/api/online/pass_it\\?(.*)$'),
  async ({url, event, params}) => {
    let ret = 'OK';
    try {
      let db = await wallet_db;
      let args = parseUrlArg(params[2]);
      if (args.host && args.realm && args.psw) {
        // step 1: decode password
        let psw = URL_SECRET.decodePsw(Buffer.from(args.psw,'hex'));
        
        // step 2: ensure rootBip ready and check psw
        let accInfo = await db.get('config','account');
        if (!accInfo)
          ret = 'NOT_READY';
        else {
          if (!rootBip.hasInit()) {
            let bipInfo = configCheckBip(psw,accInfo);
            if (bipInfo === null)  // bipInfo is null if psw is invalid
              ret = 'WAIT_PASS';
          }
          else {
            if (!verifyAccoutPass(psw,accInfo)) // psw is invalid
              ret = 'WAIT_PASS';
          }
        }
        
        // step 3: perform authority
        if (ret == 'OK') {  // not meet error yet
          if (args.realm != '@')
            ret = await passNalAuth(db,args.host,args.realm);
          // else, ret = 'OK', no need authority
        }
      }
      else ret = 'INVALID_ARGS';
    }
    catch(e) {
      console.log(e);
      ret = 'SYS_ERROR';
    }
    
    // step 4: return channel information
    if (ret == 'WAIT_PASS') {
      await new Promise( (resolve,reject) => {
        setTimeout(() => resolve(null),2000);  // wait 2 seconds when input psw error
      });
    }
    
    let headers = new Headers([['Content-Type','text/html']]);
    ret = '<html><body><script>window.parent.postMessage("CHAN_INFO:' + ret + '","*");</script></body></html>';
    return new Response(ret,{status:200,statusText:'',headers});
  }
);

//----

function safeCheckCard(flag, children, prefix, content) {
  let child2 = null, child3 = null, isGNCD = children.length == 3;
  let child1 = children[0] & 0x7fffffff;  // take meta-pspt as generic-pspt
  if (isGNCD) {
    child2 = children[1] & 0x7fffffff;
    child3 = children[2] & 0x7fffffff;
  }
  
  // step 1: check card flag
  let card = typeof content == 'string'? Buffer.from(content,'hex'): content;
  if (card.slice(0,4).toString('utf-8') !== flag) return 'INVALID_FLAG';
  if (isGNCD && flag != 'gncd') return 'INVALID_FLAG';
  
  // step 2: decode related fields in card
  let off = 4, n = card.length;
  let account = null, rootcode = null, realm = null, expired = null;
  while (off < n) {
    let tag = card[off], size = card[off+1];
    if (tag == 0xc1) {      // TAG_ACCOUNT
      if (flag != 'visa')
        account = card.slice(off+2,off+2+size).toString('hex');
    }
    else if (tag == 0xc2)   // TAG_ROOTCODE
      rootcode = card.slice(off+2,off+2+size).toString('hex');
    else if (tag == 0xc5) { // TAG_TARGET
      if (flag == 'visa')
        account = card.slice(off+2,off+2+size).toString('hex');
    }
    else if (tag == 0xc8)   // TAG_REALM
      realm = card.slice(off+2,off+2+size).toString('utf-8');
    else if (tag == 0xcb)   // TAG_CERT_EXPIRED
      expired = card.slice(off+2,off+2+size);
    off += (2+size);
  }
  
  if (flag != 'gncd' && account === null) return 'NO_ACCOUNT_FIELD';
  if (rootcode == null || realm === null || expired === null) return 'FIELD_MISMATCH';
  
  // step 3: check realm
  if (prefix) {
    if (realm != prefix && realm.indexOf(prefix+'+') != 0)
      return 'INVALID_REALM';   // prefix mismatch
  }
  // else, no need check realm
  
  // step 4: check rootcode
  if (isGNCD) {
    let ownerPub33 = rootBip.getDidPubkey(child1);
    if (!ownerPub33) return 'WAIT_PASS';
    let codeHa = CreateHash('sha256').update(ownerPub33).update(Buffer.from(':'+child2+'/'+child3)).digest();
    if (rootcode != codeHa.slice(0,4).toString('hex'))
      return 'ROOTCODE_MISMATCH';
  }
  else {
    let ownerPub33 = rootBip.getDidPubkey(null);
    if (!ownerPub33) return 'WAIT_PASS';
    let codeHa = CreateHash('sha256').update(ownerPub33).update(Buffer.from(':'+child1)).digest();
    if (rootcode != codeHa.slice(0,4).toString('hex'))
      return 'ROOTCODE_MISMATCH';
  }
  
  // step 5: check account
  let role = realm.split('+')[1] || '';
  if (isGNCD) {
    return [rootBip.getDidPubkey([child1,child2,child3]).toString('hex'),expired.readUInt32BE(0),role];
  }
  else {
    let targPubkey = rootBip.getDidPubkey(child1);
    if (account && account.length == 40) {
      if (ripemdHash(targPubkey).toString('hex') != account)
        return 'PUBKEY_MISMATCH';
    }
    else {
      if (account && targPubkey.toString('hex') != account) // account should be pubkey33
        return 'PUBKEY_MISMATCH'; // pubkey33 mismatch
    }
    return [targPubkey.toString('hex'),expired.readUInt32BE(0),role];
  }
}

workbox.routing.registerRoute(
  new RegExp('^(http|https)://([^/]+)/account/api/online/add_card\\?(.*)$'),
  async ({url, event, params}) => {
    // step 1: get host and card
    let host = event.request.referrer || '';
    host = (host.split('://')[1] || '').split('/')[0];
    
    let args = parseUrlArg(params[2]), comefrom = args.from || '', card = args.card || '';
    card = Buffer.from(card,'hex');
    
    // step 2: check card
    let desc = '', flag = card.slice(12,16).toString('utf-8');
    if (flag != 'pspt' && flag != 'visa' && flag != 'gncd')
      desc = "\u9a8c\u8bc1\u5931\u8d25\uff1a\u672a\u77e5\u5361\u8bc1\u683c\u5f0f"; // unknown card type
    else {
      let crc = CreateHash('sha256').update(card.slice(0,-4)).digest().slice(0,4).toString('hex');
      if (crc != card.slice(-4).toString('hex'))
        desc = "\u9a8c\u8bc1\u5931\u8d25\uff1a\u6821\u9a8c\u7801\u4e0d\u5339\u914d"; // verify code mismatch
      else {
        if (!rootBip.hasInit())
          desc = "NAL \u8d26\u53f7\u5c1a\u672a\u767b\u5f55\uff0c\u8bf7\u5148\u5728\u7f51\u9875\u5b8c\u6210\u767b\u5f55"; // should login at web page first
      }
    }
    
    if (!desc) {
      let child1 = card.readUInt32BE(0), child2 = null, child3 = null;
      let child, children = [child1];
      if (flag == 'gncd') {
        child2 = card.readUInt32BE(4);
        child3 = card.readUInt32BE(8);
        children.push(child2,child3);
        child = child1 + ',' + child2 + ',' + child3;
      }
      else child = child1 + '';
      
      card = card.slice(12,-4);  // child12 + card_content + crc4
      
      let info = safeCheckCard(flag,children,host,card);
      if (typeof info == 'string')
        desc = "\u9a8c\u8bc1\u5931\u8d25\uff1a" + info; // verify fail
      else {
        // step 4: save card to DB
        let pubkey = info[0];
        let expired = info[1] * 60;
        let role = info[2];
        let save_tm = Math.floor((new Date()).valueOf() / 1000);
        let card2 = {host,flag,role,child,pubkey,content:card.toString('hex'),save_tm,expired:0-expired};
        if (comefrom) card2.comefrom = comefrom;
        
        await (await wallet_db).put('recent_cards',card2);
        
        let cardDesc = role? (flag+':'+role): flag;
        desc = "\u5df2\u5c06 " + cardDesc + " \u4fdd\u5b58\u5230\u672c\u5730\u6570\u636e\u5e93"; // have saved to local DB
      }
    }
    
    // step 5: return html result
    let ret = `<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"></head><body><script>alert("${desc}");</script></body></html>`;
    let headers = new Headers([['Content-Type','text/html']]);
    return new Response(ret,{status:200,statusText:'',headers});
  }
);

workbox.routing.registerRoute(
  new RegExp('^(http|https)://[^/]+/account/api/[^/]+$'),
  new workbox.strategies.NetworkOnly()
);

//--------

const EMPTY_STRING = Buffer.alloc(32,0);

function generateRand(num) {
  let ret = Buffer.alloc(num,0);
  for (let i=0; i < num; i++) {
    ret[i] = Math.floor(Math.random() * 256);  // 0 ~ 255
  }
  return ret;
}

function _toDER(x) {
  let i = 0;
  while (x[i] === 0) ++i;
  if (i === x.length) return ZERO;
  x = x.slice(i);
  if (x[0] & 0x80) return Buffer.concat([ZERO,x],1+x.length);
  return x;
}

function _fromDER(x) {
  if (x[0] === 0x00) x = x.slice(1);
  const buffer = Buffer.alloc(32,0);
  const bstart = Math.max(0,32-x.length);
  x.copy(buffer,bstart);
  return buffer;
}

function signDer(bip, hash) {
  const priv = bip.privateKey;
  if (!priv) throw new Error('Missing private key');
  
  const sig = ECC.sign(hash, priv);
  const r = _toDER(sig.slice(0, 32));
  const s = _toDER(sig.slice(32, 64));
  return bip66.encode(r,s);
}

function verifyDer(bip, hash, sig) {
  const decoded = bip66.decode(sig);
  const r = _fromDER(decoded.r);
  const s = _fromDER(decoded.s);
  return bip.verify(hash,Buffer.concat([r,s],64));
}

function figerprintOf(pubkey) {
  let tmp = CreateHash('sha256').update(pubkey).digest();
  tmp = CreateHash('ripemd160').update(tmp).digest().slice(0,4);
  return parseInt(tmp.toString('hex'),16);
}

function hash256_d(s) { // make double hash, s is utf-8 string or Buffer
  if (!(s instanceof Buffer)) {
    if (typeof s != 'string') s = s + '';
    s = Buffer.from(s); // load as utf-8
  }
  return CreateHash('sha256').update(CreateHash('sha256').update(s).digest()).digest();
}

function ripemdHash(buf) {
  let ha = CreateHash('sha256').update(buf).digest();
  return CreateHash('ripemd160').update(ha).digest();
}

function b36checkEncode(payload, prefix) {
  if (!prefix) prefix = 'rid1';
  
  let ha = ripemdHash(payload);
  let code4 = CreateHash('sha256').update(Buffer.from(prefix)).update(ha).digest();
  code4 = CreateHash('sha256').update(code4).digest().slice(0,4); // double hash256
  
  return prefix + base36.encode(Buffer.concat([ha,code4]));
}

const is_array = function(v) { 
  return v && typeof v === 'object' && typeof v.length === 'number' && 
    typeof v.splice === 'function' && !(v.propertyIsEnumerable('length')); 
};

function ber_encode(buf, off, tag, arg, fmt) {
  let inBuf, tp = typeof arg;
  if (tp == 'number') {  // take arg as int32
    off = buf.writeUInt8(tag,off);
    off = buf.writeUInt8(4,off);
    if (fmt == 'BE')
      return buf.writeUInt32BE(arg,off);
    else return buf.writeUInt32LE(arg,off);
  }
  else if (tp == 'string')
    inBuf = Buffer.from(arg,fmt); // uses utf-8 when fmt is undefined
  else if (is_array(arg))
    inBuf = Buffer.from(arg);
  else inBuf = arg;              // arg should be Buffer
  
  let from, len = inBuf.length;  // inBuf.length must less than 65536
  if (len > 255) {
    let hi = Math.floor(len/256), lo = len - (hi * 256);
    off = buf.writeUInt8(tag,off);
    off = buf.writeUInt8(0x82,off);
    off = buf.writeUInt8(hi,off);
    off = buf.writeUInt8(lo,off);
    from = 4;
  }
  else if (len > 127) {
    off = buf.writeUInt8(tag,off);
    off = buf.writeUInt8(0x81,off);
    off = buf.writeUInt8(len,off);
    from = 3;
  }
  else {
    off = buf.writeUInt8(tag,off);
    off = buf.writeUInt8(len,off);
    from = 2;
  }
  
  inBuf.copy(buf,off,0,len);
  return off + len;
}

function wait__(promise_obj, wait) {
  let abort_fn = null;
  let abortable_promise = Promise.race([ promise_obj,
    new Promise( function(resolve, reject) {
      abort_fn = function() { reject(new Error('TIMEOUT')) };
    })
  ]);
  
  setTimeout(()=>abort_fn(),wait);
  return abortable_promise;
}

function gen_ecdh_key(pubkey33, re_gen) {
  if (re_gen) ECDH.generateKeys();
  
  let pubKeyPoint = ECDH.getPublicKey();
  let nonce_x = pubKeyPoint.slice(1,33);  // nonce_y = pubKeyPoint.slice(33,65)
  let flag = pubKeyPoint[64] & 0x01;
  let targ_x = ECDH.computeSecret(pubkey33);
  return [flag, nonce_x, targ_x];
}

function scanCardTag(card, tag) {
  let off = 4, n = card.length;
  while (off < n) {
    let t = card[off], len = card[off+1];
    if (t === tag) return card.slice(off+2,off+2+len);
    off += (2+len);
  }
  return null;  // not found
}

function BipAccount() {
  // we hide some variables here, avoid leaking out by console.log()
  let phone = null, figerprint = null;
  let alternate_no = null, alternate_off = 0;
  let didRoot = null, pswRoot = null, secureRoot = null, realRoot = null;
  let did_realid = null;
  let selfsign_no = null, selfsign = null;
  let securebox_cipher = '';
  
  let gncd_fetch_keys = [];
  
  return {
    hasInit() {
      return !!pswRoot;
    },
    
    disableBip() {   // no need clear: figerprint
      didRoot = null;    // did
      secureRoot = null; // did/alternate/0
      realRoot = null;   // did/0/0
      pswRoot = null;    // psw/0'
      
      did_realid = null;
      
      selfsign_no = null;
      selfsign = null;
    },
    
    config(secret, accInfo, fp) {
      phone = accInfo.phone;
      alternate_off = accInfo.alternate_off;
      alternate_no = (accInfo.alternate_no + alternate_off) & 0x7fffffff;
      figerprint = fp;
      
      didRoot = bip32.fromPrivateKey(secret.slice(0,32),secret.slice(32,64));
      realRoot = didRoot.derive(0).derive(0);
      secureRoot = didRoot.derive(alternate_no).derive(0); // "alt/alternate/0" for securebox crypto
      
      did_realid = b36checkEncode(realRoot.publicKey,'rid1');
      
      selfsign_no = accInfo.selfsign_no;
      selfsign = realRoot.derive(selfsign_no);
      
      pswRoot = bip32.fromPrivateKey(secret.slice(64,96),secret.slice(96,128));
      pswRoot = pswRoot.derive(0x80000000);   // forget original psw account
    },
    
    secureboxCipher(crc, fixKey, pltPubkey, pdtPubkey) {  // get:rootBip.secureboxCipher(), set:rootBip.secureboxCipher(crc,fixKey,pltPubkey,pdtPubkey)
      if (!crc && !fixKey) {
        if (crc === null && fixKey === null)  // clear:rootBip.secureboxCipher(null,null)
          securebox_cipher = '';
      }
      else {
        ECDH.setPrivateKey(fixKey);
        let peerPub = ECDH.getPublicKey(undefined,'compressed');
        let crc4 = Buffer.from(crc,'hex');
        let r_plt = gen_ecdh_key(Buffer.from(pltPubkey,'hex'),true); // [flag,nonce,k_iv]
        let r_pdt = gen_ecdh_key(Buffer.from(pdtPubkey,'hex'),false);
        ECDH.generateKeys();  // erase for safty
        
        let msg = Buffer.concat([new Buffer([0,0,4]),crc4,new Buffer([0,alternate_off]),peerPub]);
        let encrypt = encryptMsg(r_plt[2],msg);
        encrypt = encryptMsg(r_pdt[2],encrypt);
        securebox_cipher = (r_plt[0]==1?'03':'02') + r_plt[1].toString('hex') + encrypt.toString();
      }
      return securebox_cipher;
    },
    
    info() {
      if (!didRoot || !pswRoot || !realRoot) return {figerprint};
      
      let did_figerprint = figerprintOf(didRoot.publicKey);
      let real_figerprint = figerprintOf(realRoot.publicKey);
      return { figerprint, did_figerprint, real_figerprint, did_realid, selfsign_no,
        did_pubkey: didRoot.publicKey.toString('hex'),
        real_pubkey: realRoot.publicKey.toString('hex'),
        selfsign_pubkey: selfsign.publicKey.toString('hex'),
        psw_pubkey: pswRoot.publicKey.toString('hex'),
        real_chaincode: realRoot.chainCode.toString('hex') };
    },
    
    getDidPubkey(child) {
      if (!pswRoot) return null;  // not init yet
      if (child === null) return realRoot.publicKey;
      
      if (typeof child == 'number')
        return realRoot.derive(child & 0x7fffffff).publicKey;
      else { // child must be array
        let ret = realRoot.derive(child[0] & 0x7fffffff);
        let child2 = child[1];
        if (typeof child2 == 'number') {
          ret.chainCode = EMPTY_STRING;
          ret = ret.derive(child2 & 0x7fffffff);
          let child3 = child[2];
          if (typeof child3 == 'number')
            ret = ret.derive(child3 & 0x7fffffff);
        }
        return ret.publicKey;
      }
    },
    
    signDisabling(tm) {
      let ha = CreateHash('sha256').update(Buffer.from('NBC_DISABLE_PSPT:'+tm)).digest();
      return [ b36checkEncode(realRoot.publicKey,'rid1'),
        signDer(realRoot,ha).toString('hex') ];
    },
    
    changeSelfSign(no) {
      if (realRoot) {
        try {
          let tmp = realRoot.derive(no);
          selfsign_no = no;
          selfsign = tmp;
          return tmp.publicKey.toString('hex');
        }
        catch(e) { console.log(e); }
      }
      return null;
    },
    
    sessionSign(child, host, realm, ctx) {
      let b = child.split(',');  // ['child1'] or ['child1','child2','child3']
      let child1 = parseInt(b[0]) & 0x7fffffff;  // child1 >= 0x80000000 means meta-passport
      let didAcc = realRoot.derive(child1);
      if (b.length == 3) {
        let child2 = parseInt(b[1]) & 0x7fffffff;
        let child3 = parseInt(b[2]) & 0x7fffffff;
        didAcc.chainCode = EMPTY_STRING;
        didAcc = didAcc.derive(child2).derive(child3);
      }
      
      let s = host + '+' + realm;
      if (ctx) s += ':';   // ctx can be ''
      let ha = CreateHash('sha256').update(Buffer.concat([Buffer.from(s),Buffer.from(ctx,'hex')])).digest();
      return [didAcc.publicKey,signDer(didAcc,ha)];
    },
    
    encryptSecurebox(ctx) {
      let msg = CryptoJS.enc.Utf8.parse(ctx);
      let padding = msg.sigBytes % 16;
      if (padding) padding = 16 - padding;
      
      let key_iv = secureRoot.privateKey;  // 32 bytes
      let segment = AesCtrEncrypt(key_iv.slice(0,16),key_iv.slice(16,32),msg);
      return [msg.sigBytes,padding,segment.toString(CryptoJS.enc.Base64)];
    },
    
    decryptSecurebox(ctx) {
      let key_iv = secureRoot.privateKey;  // 32 bytes
      let ret = AesCtrDecrypt(key_iv.slice(0,16),key_iv.slice(16,32),ctx); // decrypt with CTR and zero padding
      return ret.toString(CryptoJS.enc.Hex);
    },
    
    _newPassport(isAcc20, realm, tmSegment, child, didAcc, now_tm, expiredTm,adminFP) {
      // step 1: get realm, loginSession, rootCode
      realm = realm.replace(/[ <>=,"']/g,'');  // can not contain: space < > = , ' "
      realm = realm.slice(0,96);  // max keep 96 char
      
      let realmUID = Buffer.concat([Buffer.from(realm+':'),realRoot.publicKey]);
      realmUID = CreateHash('sha256').update(realmUID).digest();
      let loginSess = ripemdHash(Buffer.concat([realmUID,Buffer.from(':'+tmSegment)])); // make loginSess20
      
      let rootCode = Buffer.concat([realRoot.publicKey,Buffer.from(':'+child)]);
      rootCode = CreateHash('sha256').update(rootCode).digest().slice(0,4);
      
      // step 2: setup passport content
      let off = 0, buf = Buffer.allocUnsafe(192);
      buf[off++] = 112; buf[off++] = 115;  // header 'pspt'
      buf[off++] = 112; buf[off++] = 116;
      
      if (isAcc20)  // meta passport use account20 by default
        off = ber_encode(buf,off,0xc1,ripemdHash(didAcc.publicKey));
      else off = ber_encode(buf,off,0xc1,didAcc.publicKey); // generic passport use account33 by default
      
      off = ber_encode(buf,off,0xc2,rootCode);
      off = ber_encode(buf,off,0xc3,loginSess);
      off = ber_encode(buf,off,0xc8,realm);
      off = ber_encode(buf,off,0xca,adminFP);
      off = ber_encode(buf,off,0xcb,expiredTm,'BE');  // BE uint4 by minutes
      off = ber_encode(buf,off,0xcc,now_tm); // sessType1 + minutes4
      
      // step 3: make signature
      let body = buf.slice(0,off);
      let sig = CreateHash('sha256').update(body).digest();
      sig = ECC.sign(sig,didAcc.privateKey);
      return [child,body,sig,realm,expiredTm,didAcc.publicKey];
    },
    
    newPassport(isAcc20, sessType, realm, child, now, expiredTm) {
      // step 1: caculate time related variables
      let tmSegment, maxExpired, nowSec = parseInt((new Date()).valueOf()/1000);
      if (!now)   // creating meta-passport
        tmSegment = 0;
      else tmSegment = Math.floor(nowSec / refresh_periods[sessType & 0x07]);
      now = parseInt(nowSec / 60);  // by minutes
      
      maxExpired = now + 20150;  // by minutes, 14d - 10m, can not more than 14 days
      if (typeof expiredTm == 'number') {
        expiredTm = parseInt(expiredTm / 60);  // conver from seconds to minutes
        expiredTm = Math.max(now+10,Math.min(maxExpired,expiredTm)); // now+10 means that should at least have 10 minutes
      }
      else expiredTm = maxExpired;
      
      let now_tm = Buffer.allocUnsafe(5);
      now_tm[0] = sessType & 0xff;
      now_tm.writeUInt32BE(tmSegment==0?0:now,1);  // BE uint4 by minutes
      
      // step 2: derive did/0/0/child
      if (typeof child != 'number')
        child = Math.floor(Math.random() * 0x7fffffff) + 1; // child != 0
      child = child & 0x7fffffff;
      let didAcc = realRoot.derive(child);
      
      // step 3: setup passport
      if (!realm) realm = '';
      let ret = this._newPassport(isAcc20,realm,tmSegment,child,didAcc,now_tm,expiredTm,REAL_MANAGER.rsp_admin_fp);
      if (tmSegment == 0) ret.push(did_realid);
      return ret;
    },
    
    newSelfSignPspt(sessType, realm, expiredTm) {  // expiredTm is seconds or undefined
      // step 1: caculate time related variables
      let nowSec = parseInt((new Date()).valueOf()/1000);
      let now = parseInt(nowSec / 60);  // by minutes
      let tmSegment = Math.floor(nowSec / refresh_periods[sessType & 0x07]);
      
      maxExpired = now + 20150;  // by minutes, 14d - 10m, can not more than 14 days
      if (typeof expiredTm == 'number') {
        expiredTm = parseInt(expiredTm / 60);  // conver from seconds to minutes
        expiredTm = Math.max(now+10,Math.min(maxExpired,expiredTm)); // now+10 means that should at least have 10 minutes
      }
      else expiredTm = maxExpired;
      
      let now_tm = Buffer.allocUnsafe(5);
      now_tm[0] = sessType & 0xff;
      now_tm.writeUInt32BE(now,1);  // BE uint4 by minutes
      
      // step 2: setup passport
      let adminFP = ripemdHash(selfsign.publicKey).slice(0,4);
      return this._newPassport(false,realm,tmSegment,selfsign_no,selfsign,now_tm,expiredTm,adminFP);
    },
    
    genGreencardCipher(adminPub, expireMins, visaCard, suggestChild, realHost, callback) { // suggestChild is null or string
      let child1 = parseInt(visaCard.child) & 0x7fffffff;
      let child2 = Math.floor(Math.random()*0x7fffffff) + 1;
      let child3 = Math.floor(Math.random()*0x7fffffff) + 1; 
      if (suggestChild) {
        let b = suggestChild.split(',');
        if (b.length == 2) {  // can reuse old one
          child2 = parseInt(b[0]) & 0x7fffffff;
          child3 = parseInt(b[1]) & 0x7fffffff;
        }
      }
      
      let ownerAcc = realRoot.derive(child1);
      ownerAcc.chainCode = EMPTY_STRING;
      let targAcc = ownerAcc.derive(child2).derive(child3);
      
      let rootcode = Buffer.concat([ownerAcc.publicKey,Buffer.from(':'+child2+'/'+child3)]);
      rootcode = CreateHash('sha256').update(rootcode).digest().slice(0,4);
      let now_tm = Math.floor((new Date()).valueOf() / 60000);  // by minutes
      
      let bufCard = Buffer.from(visaCard.content,'hex');
      let cipherSize = 55 + bufCard.length;
      let padding = cipherSize % 16;
      if (padding) padding = (16 - padding);
      
      let authExpired = scanCardTag(bufCard,0xcb);  // TAG_CERT_EXPIRED, by minutes
      if (authExpired) {
        authExpired = authExpired.readUInt32BE(0);
        if (expireMins > authExpired) expireMins = authExpired;
      }
      let maxAuth = scanCardTag(bufCard,0xcf);  // TAG_MAX_AUTH_TIME, by minutes
      if (maxAuth) {
        maxAuth = now_tm + maxAuth.readUInt32BE(0);
        if (expireMins > maxAuth) expireMins = maxAuth;
      }
      
      let off = 0, cipherBuf = Buffer.alloc(cipherSize+padding,0);
      adminPub.copy(cipherBuf,off); off += 33;  // buf.copy(targBuffer,targStart,sourStart,sourEnd)
      rootcode.copy(cipherBuf,off); off += 4;
      cipherBuf.writeUInt32BE(child2,off); off += 4;
      cipherBuf.writeUInt32BE(child3,off); off += 4;
      cipherBuf.writeUInt32BE(now_tm,off); off += 4;
      cipherBuf.writeUInt32BE(expireMins,off); off += 4;
      cipherBuf.writeUInt16BE(bufCard.length,off); off += 2;  // off = 55
      bufCard.copy(cipherBuf,off); off += bufCard.length;
      if (padding) generateRand(padding).copy(cipherBuf,off);
      
      // encrypt cipherBuf
      ECDH.generateKeys();
      let tmpKey = ECDH.getPrivateKey();
      let r_plt = gen_ecdh_key(REAL_MANAGER.csp_plt_pubkey,false); // [flag,nonce,k_iv]
      let r_pdt = gen_ecdh_key(REAL_MANAGER.csp_pdt_pubkey,false);
      ECDH.generateKeys();  // erase for safty
      
      tmpPub = (r_plt[0]?'03':'02') + r_plt[1].toString('hex');
      gncd_fetch_keys.push([tmpPub,r_plt[2],r_pdt[2]]);
      if (gncd_fetch_keys.length > 5)  // max hold 5 items
        gncd_fetch_keys.splice(0,gncd_fetch_keys.length - 3);
      
      cipherBuf = encryptMsg(r_plt[2],cipherBuf);
      cipherBuf = encryptMsg(r_pdt[2],cipherBuf);
      
      info = [now_tm,expireMins,child1,child2,child3,targAcc.publicKey,rootcode,tmpPub+cipherBuf.toString()];
      
      if (realHost) {  // need report to RSP
        let reportPath = Buffer.alloc(12,0);
        reportPath.writeUInt32BE(child1,0);
        reportPath.writeUInt32BE(child2,4);
        reportPath.writeUInt32BE(child3,8);
        let body = {rid:did_realid,path:reportPath.toString('hex'),rootcode:rootcode.toString('hex')};
        
        let url = 'https://' + realHost + '/cards/report';
        wait__( fetch(url,{method:'POST',body:JSON.stringify(body),referrerPolicy:'no-referrer'}),10000).then( res => {
          if (res.status == 200)
            return res.json();
          else return null;
        }, e => null).then( res2 => {
          if (res2 && res2.result == 'OK')
            callback(info);
          else callback(null)
        });
      }
      else callback(info);
    },
    
    decryptGreencard(hexPubkey, content, padding) {  // content should be base64 string
      for (let i=0,item; item=gncd_fetch_keys[i]; i++) {
        if (item[0] === hexPubkey) {
          let cardMsg = decryptMsg(item[2],content); // by pdt key
          cardMsg = decryptMsg(item[1],cardMsg.toString(CryptoJS.enc.Base64)); // by plt key
          cardMsg = cardMsg.toString(CryptoJS.enc.Hex);
          if (padding)
            return cardMsg.slice(0,0-padding-padding);
          else return cardMsg;
        }
      }
      return '';
    },
  };
}

const rootBip = BipAccount();

async function findGreenCard(db, host, pubkey) {
  let now = Math.floor((new Date()).valueOf() / 1000);
  let range = IDBKeyRange.bound([host,0-now-1209600],[host,0-now-3600]); // 1209600 is 14 days
  let items = await db.getAllFromIndex('recent_cards','host_expired',range,64);
  
  for (let i=0; i < items.length; i++) {
    let item = items[i];
    if (item.flag == 'gncd' && item.pubkey == pubkey)
      return item.child;
  }
  return null;
}

self.addEventListener('message', async event => {
  // console.log(`SW receive message: ${event.data}`);
  try {
    let prefix = event.data[0] === '?'? '?': '';
    let msg = JSON.parse(prefix? event.data.slice(1): event.data);
    let id = msg.id || 0;
    
    if (msg.cmd == 'list_wait_sign') {  // most often call, so we put it at the first
      if (!rootBip.hasInit()) {
        event.source.postMessage(prefix+JSON.stringify({id,result:'WAIT_PASS'}));
        return;
      }
      
      let items = [];
      let host = msg.param[0], magic = msg.param[1];
      if (host === NAL_WEBHOST) { // only NAL official site can list
        let cfg = await (await wallet_db).get('config',host);
        if (cfg?.sw_magic === magic) {
          let now = Math.ceil((new Date()).valueOf() / 1000);
          let range = IDBKeyRange.bound(-now,3600-now);  // only list recent 1 hour
          
          // let tx = (await wallet_db).transaction('wait_sign','readonly');
          // items = await tx.store.index('request_tm').getAll(range,2); // max get recent 2 items
          items = await (await wallet_db).getAllFromIndex('wait_sign','request_tm',range,2);
        }
      }
      
      event.source.postMessage(prefix+JSON.stringify({id,result:items}));
    }
    
    else if (msg.cmd == 'pass_sign') {
      let ret = 'FAILED';
      let host = msg.param[0], magic = msg.param[1], tm = msg.param[2];
      
      if (typeof host == 'string' && host) { // request psw verification
        let cfg = await (await wallet_db).get('config',host);
        if (cfg?.sw_magic === magic) {
          let realm = msg.param[3] || '';
          let db = await wallet_db;
          
          if (realm) { // request signature, regist to 'wait_sign' table first
            let child = msg.param[4];
            let content = msg.param[5] || '';  // is hex-string
            let rsvd = msg.param[6] || '';
            let request_tm = 0 - tm;  // -N for easy filter
            let sign_tm = 0;
            
            let targSegm = realm.split('+');
            let isLoginCmd = targSegm.length == 2 && targSegm[1] == 'login';
            if (!child)  // child=0 is reserved
              child = isLoginCmd? '1': cfg.login_child;
            else {
              if (typeof child == 'string' && child.slice(0,5) == 'gncd:')
                child = await findGreenCard(db,host,child.slice(5));
            }
            
            if (!child)
              ret = 'NOT_LOGIN';
            else if (isLoginCmd) {
              child = child + '';
              await db.put('wait_sign',{child:child,host,realm,content,request_tm,sign_tm});
              ret = 'ADDED';
            }
            else {
              child = child + '';
              let role = targSegm[0], action = targSegm[1];
              let roleInfo = cfg.strategy.roles[role];
              let actionLv = action && cfg.strategy.actions[action];
              
              if (role != cfg.login_role || !roleInfo)
                ret = 'INVALID_ROLE';
              else if (typeof actionLv != 'number')
                ret = 'INVALID_ACTION';
              else if (Math.floor((new Date()).valueOf()/1000) >= cfg.login_expired)
                ret = 'NOT_LOGIN';
              else {
                ret = 'NONE';
                
                let needPass = false;
                let checker = roleInfo.actions[action];
                if (typeof checker != 'string')
                  ret = 'NO_ACTION';
                else if (checker == 'pass')
                  needPass = true;
                else if (checker == 'rsvd') {
                  let accInfo = await db.get('config','account');
                  if (!accInfo || getAccountRsvd(accInfo) !== rsvd) {
                    ret = 'INVALID_RSVD';
                    rootBip.disableBip();
                  }
                  // else, rsvd is correct
                }
                else {  // checker == 'auto'
                  if (roleInfo.level == actionLv)
                    needPass = true;
                  else if (roleInfo.level < actionLv)
                    ret = 'NOT_AUTHORIZED';
                  // else, passed
                }
                
                if (ret == 'NONE') { // not meet error yet
                  if (needPass) {
                    await db.put('wait_sign',{child,host,realm,content,request_tm,sign_tm});
                    ret = 'ADDED';
                  }
                  else {
                    if (!rootBip.hasInit())
                      ret = 'WAIT_PASS';
                    else {
                      let info2 = rootBip.sessionSign(child,host,realm,content);
                      ret = {realm,child,pubkey:info2[0].toString('hex'),signature:info2[1].toString('hex')};
                    }
                  }
                }
              }
            }
            
            event.source.postMessage(prefix+JSON.stringify({id,result:ret}));
            return;
          }
          // else, query signature result from 'sign_history' table
          
          let range = IDBKeyRange.upperBound(0 - tm);
          let items = await db.getAllFromIndex('sign_history','sign_tm',range,10);
          let info = items.find(item => item.host === host);
          if (info)  // info.signature maybe undefined if is canceled by NAL
            ret = {child:info.child, pubkey:info.pubkey, realm:info.realm, signature:info.signature||''};
          else ret = 'UNSIGN';  // no item found
        }
      }
      
      event.source.postMessage(prefix+JSON.stringify({id,result:ret}));
    }
    
    else if (msg.cmd == 'do_wait_sign') {
      // return: 'OK' 'WAIT_PASS' 'NOT_READY' 'FAILED' 'TIMEOUT' 'INVALID_ROLE'
      let ret = 'OK';
      let psw = msg.param[0], host = msg.param[1], magic = msg.param[2], targHost = msg.param[3];
      
      if (typeof psw == 'string' && psw && typeof host == 'string' && host == NAL_WEBHOST) {
        // step 1: check password
        let db = await wallet_db;
        let accInfo = await db.get('config','account');
        if (!accInfo)
          ret = 'NOT_READY';
        else {
          let cfg = await db.get('config',host);
          if (cfg?.sw_magic === magic) {
            if (!rootBip.hasInit()) {
              bipInfo = configCheckBip(psw,accInfo);
              if (bipInfo === null)  // bipInfo is null if psw is invalid
                ret = 'WAIT_PASS';
            }
            else if (!verifyAccoutPass(psw,accInfo)) // psw mismatch
              ret = 'WAIT_PASS';
          }
          else ret = 'FAILED';  // unexpected situation
        }
        if (ret != 'OK') {
          if (ret == 'WAIT_PASS')
            setTimeout(() => event.source.postMessage(prefix+JSON.stringify({id,result:ret})),2000);
          else event.source.postMessage(prefix+JSON.stringify({id,result:ret}));
          return;
        }
        
        // step 2: perform authority
        if (typeof targHost == 'string' && targHost)
          ret = await passNalAuth(db,targHost);
        // else, meet fake message, ignore processing
      }
      
      event.source.postMessage(prefix+JSON.stringify({id,result:ret}));
    }
    
    else if (msg.cmd == 'rmv_wait_sign') {
      let ret = 'NONE';
      let host = msg.param[0], magic = msg.param[1], targHost = msg.param[2];
      if (typeof host == 'string' && host) {
        let db = await wallet_db;
        let cfg = await db.get('config',host);
        
        if (cfg && cfg.sw_magic === magic) {
          let targ = host;
          if (typeof targHost == 'string' && targHost) {
            let info = await db.get('wait_sign',targHost);
            if (info) {
              await db.delete('wait_sign',targHost);  // remove by admin peer
              
              let now = Math.floor((new Date()).valueOf() / 1000);
              info.sign_tm = 0 - now;  // cancel sign: no info.signature, no info.pubkey
              await db.put('sign_history',info);
            }
          }
          else await db.delete('wait_sign',host); // remove by self peer
          ret = 'OK';
        }
      }
      
      event.source.postMessage(prefix+JSON.stringify({id,result:ret}));
    }
    
    else if (msg.cmd == 'list_cards') {
      let ret = 'NONE';
      let host = msg.param[0], magic = msg.param[1], psptAlso=msg.param[2], tillTm = msg.param[3];
      if (typeof host == 'string' && host) {
        let db = await wallet_db;
        let cfg = await db.get('config',host); // cfg:{name,sw_magic,magic_tm,strategy,storage}+{...other_cfg}
        if (cfg && cfg.sw_magic === magic) {
          let fromNAL = host === NAL_WEBHOST;
          let targHost = msg.param[4];
          if (!fromNAL) {     // when not call from NAL
            targHost = host;  // only query website itself
            psptAlso = false; // exclude passport
            tillTm = null;    // fixed by default
          }
          else {
            if (!targHost) targHost = host;
          }
          
          let now = Math.floor((new Date()).valueOf() / 1000);
          if (typeof tillTm != 'number') {
            let sessType = cfg.strategy?.session_type;
            if (typeof sessType != 'number') sessType = 1;
            let period = session_periods[sessType & 0x07];
            tillTm = now + period;  // still alive (not expired) after one period
          }
          let metaExpired = tillTm;
          if (psptAlso)
            metaExpired = now + (cfg.strategy?.meta_pspt_expired || 336) * 3600; // 336h is 14 days
          metaExpired = 0 - Math.min(tillTm,metaExpired);  // meta passport reused only within 12 hours by default, it can be changed by strategy.meta_pspt_expired
          
          let range = IDBKeyRange.bound([targHost,0-now-630720000],[targHost,0-tillTm]);  // 630720000 is 20 years
          let items = await db.getAllFromIndex('recent_cards','host_expired',range,36); // max scan 36 cards
          
          ret = [];
          let gncdList = [];
          items.forEach( item => { // it sorted by 'expired' field
            if (!fromNAL) { // when not call from NAL, only includes visa card
              if (item.flag == 'visa')
                ret.push({ flag:'visa', role:item.role, comefrom:item.comefrom||'',
                  expired:item.expired, child:item.child, pubkey:item.pubkey, content:null });
              else if (item.flag == 'gncd') gncdList.push(item);
            }
            else {
              if (item.flag == 'pspt') {
                if (!psptAlso) return;
                if (parseInt(item.child) >= 0x80000000) {  // is meta passport  // item.child can be 'child1,child2,child3'
                  if (item.expired < metaExpired) ret.push(item); // not expired, negative compare
                }
                else ret.push(item);
              }
              else ret.push(item);
            }
          });
          
          if (!fromNAL && gncdList.length) {  // try replace visa with gncd
            let minExpired = now + 3600;
            ret.forEach( item => {
              for (let ii=0,item2; item2=gncdList[ii]; ii++) {
                if (item2.role == item.role && Math.abs(item2.expired) > minExpired) {
                  item.child = 'gncd';
                  item.expired = item2.expired;
                  item.pubkey = item2.pubkey;
                  item.content = item2.content;
                  break;
                }
              }
            });
          }
        }
      }
      event.source.postMessage(prefix+JSON.stringify({id,result:ret}));
    }
    
    else if (msg.cmd == 'count_cards') {
      let ret = 'NONE';
      let host = msg.param[0], magic = msg.param[1], tillTm = msg.param[2];
      if (host === NAL_WEBHOST) {
        let db = await wallet_db;
        let cfg = await db.get('config',host); // cfg:{name,sw_magic,magic_tm,strategy,storage}+{...other_cfg}
        if (cfg && cfg.sw_magic === magic) {
          if (typeof tillTm != 'number')
            tillTm = Math.floor((new Date()).valueOf() / 1000);
          let range = IDBKeyRange.upperBound(0-tillTm);
          let storeIndex = db.transaction(['recent_cards'],'readonly').objectStore('recent_cards').index('expired');
          
          let d = {};
          await storeIndex.openCursor(range).then(function collectItem(cursor) {
            if (cursor) {
              let card = cursor.value, hostItem = d[card.host];
              if (typeof hostItem == 'undefined') d[card.host] = hostItem = {};
              hostItem[card.flag] = (hostItem[card.flag] || 0) + 1;
              return cursor.continue().then(collectItem);
            }
          });
          ret = [];
          for (let k in d) ret.push([k,d[k]]);
        }
      }
      
      event.source.postMessage(prefix+JSON.stringify({id,result:ret}));
    }
    
    else if (msg.cmd == 'get_pspt') {
      let ret = 'NONE', cfg = null;
      let host = msg.param[0], magic = msg.param[1], is_meta = !!msg.param[2];
      let db = await wallet_db;
      
      if (typeof host == 'string' && host) {
        cfg = await db.get('config',host);
        if (cfg && cfg.sw_magic !== magic) cfg = null;
      }
      if (cfg) {
        let sessType = msg.param[3];
        if (typeof sessType != 'number') sessType = 1;
        
        let period = session_periods[sessType & 0x07];
        let now = Math.floor((new Date()).valueOf() / 1000);
        let metaExpired = 0 - now - Math.min(period,(cfg.strategy?.meta_pspt_expired || 12) * 3600);
        let range = IDBKeyRange.bound([host,0-now-1209600],[host,0-now-period]); // 1209600 is 14 days
        let items = await db.getAllFromIndex('recent_cards','host_expired',range,32);
        
        let card = null;
        for (let i=0; i < items.length; i++) {
          let item = items[i];
          if (item.flag == 'pspt') {
            if (is_meta && parseInt(item.child) >= 0x80000000 && item.expired < metaExpired) {
              card = item;
              break;
            }
            else if (!is_meta && parseInt(item.child) < 0x80000000) {
              card = item;
              break;
            }
          }
        }
        
        if (card) {
          ret = { state:'OLD_PSPT', content:card.content, realm:host, 
            child:parseInt(card.child) & 0x7fffffff, pubkey:card.pubkey,
            expired:card.expired, is_meta };
        }
        else {  // !card
          if (!rootBip.hasInit())
            ret = 'WAIT_PASS';
          else {  // wait fetching passport signature
            let child = Math.floor(Math.random() * 0x7fffffff) + 1; // child != 0
            let info = rootBip.newPassport(is_meta,sessType,host,child,is_meta?0:now);
            
            let accInfo = await db.get('config','account'); // accInfo must exist
            let body = { passport:info[1].toString('hex'),
              self_sign:info[2].toString('hex'), expired:info[4]*60, child, // child is number
              pubkey:info[5].toString('hex') };
            let option = {method:'POST',body:JSON.stringify(body),referrerPolicy:'no-referrer'};
            
            let realUrl = 'https://' + (accInfo.real_sp || DEFAULT_REAL_SERVER) + '/cards/pspt/' + info[6];
            ret = await wait__(fetch(realUrl,option),30000).then( res => {
              if (res.status == 200)
                return res.json();
              else return null;   // ignore other res.status
            }, e => null ).then( data => {
              if (!data || !data.signature)
                return 'REQUEST_FAILED';
              else {
                let tmp = new Buffer([0xdf,data.signature.length >>> 1]);
                let passport = body.passport + tmp.toString('hex') + data.signature;
                let child2 = body.child;  // body.child is 1~0x7fffffff
                if (is_meta) child2 += 0x80000000;
                
                let info2 = safeCheckCard('pspt',[child2],host,passport);
                if (typeof info2 == 'string')
                  return info2;  // meet error
                else {
                  let pubkey = info2[0];
                  let expired = info2[1] * 60;
                  let save_tm = Math.floor((new Date()).valueOf() / 1000);
                  let card2 = { host, flag:'pspt', role:'', child:child2+'',
                    pubkey, content:passport, save_tm, expired:0-expired };
                  db.put('recent_cards',card2); // no waiting
                  
                  return { is_meta, state:'NEW_PSPT', content:passport, realm:host,
                    child:body.child, pubkey:body.pubkey, expired:body.expired };
                }
              }
            });  // end of await fetch
          }
        }
      }
      
      event.source.postMessage(prefix+JSON.stringify({id,result:ret}));
    }
    
    else if (msg.cmd == 'get_gncd') {
      let ret = 'NONE', cfg = null;
      let host = msg.param[0], magic = msg.param[1], role = msg.param[2];
      let child = msg.param[3], adminPub = msg.param[4];
      if (child) child = parseInt(child);  // ensure be number
      let db = await wallet_db;
      
      if (!rootBip.hasInit())
        ret = 'WAIT_PASS';
      else if ( typeof host == 'string' && host && typeof role == 'string' &&
        typeof child == 'number' && typeof adminPub == 'string' && adminPub) {
        cfg = await db.get('config',host);
        if (cfg && cfg.sw_magic !== magic) cfg = null;
      }
      
      if (cfg) {
        let expireMins = msg.param[5] || 20160;  // default 14 days
        let reuseMins = msg.param[6];
        
        adminPub = Buffer.from(adminPub,'hex');
        
        let card = null, accInfo = null, cryptoHost = null;
        if (adminPub.length == 33 && typeof expireMins == 'number') {
          card = await db.get('recent_cards',[host,'visa',role,child+'']);
          if (card) {
            accInfo = await db.get('config','account');
            cryptoHost = accInfo?.crypto_host;
          }
        }
        
        if (!card)
          ret = 'NO_CARD';
        else if (!cryptoHost)
          ret = 'NETWORK_ERROR';
        else {
          if (typeof reuseMins != 'number') {
            let sessType = cfg.strategy?.session_type;
            let sessLimit = cfg.strategy?.session_limit;
            if (typeof sessType == 'number' && typeof sessLimit == 'number') {
              reuseMins = Math.floor(refresh_periods[sessType&0x07] * sessLimit / 60);
              if (reuseMins > 20160) reuseMins = 20160;  // 20160 is 14 days, max reuse expiring-14-days card
            }
            else reuseMins = 2880;  // 0 for no reuse, 2880 minutes is 2 days, can reuse expiring-2-days card 
          }
          
          let now = Math.floor((new Date()).valueOf() / 1000);
          expireMins = Math.floor(now / 60) + expireMins;  // convert to till time
          
          let suggestCard = null;
          let suggestExp = 0;
          let suggestPre = child + ',';
          let suggestChild = '';  // default null means generating new one
          if (reuseMins) {
            let range = IDBKeyRange.bound([host,0-now-1209600],[host,0-now+reuseMins*60]); // 1209600 is 14 days
            let items = await db.getAllFromIndex('recent_cards','host_expired',range,36);
            
            for (let i=0; i < items.length; i++) {
              let item = items[i];
              if (item.flag == 'gncd' && item.child.indexOf(suggestPre) == 0) {
                if (item.role === role) { // same role, meet best one
                  suggestChild = item.child.slice(suggestPre.length);
                  suggestExp = Math.abs(item.expired);
                  if (suggestExp > now + 3600) // at least expiring after 1 hour
                    suggestCard = item; // reuse it, card maybe just recent expired, it must already report to RSP
                  break;
                }
              }
            }
          }
          
          if (suggestCard) {  // reuse recent one
            ret = { role, expired: Math.floor(suggestExp/60),
              targ_pubkey:suggestCard.pubkey, card:suggestCard.content };
            event.source.postMessage(prefix+JSON.stringify({id,result:ret}));
            return;
          }
          
          let realHost = accInfo.real_sp || DEFAULT_REAL_SERVER; // not null, will report to RSP
          rootBip.genGreencardCipher(adminPub,expireMins,card,suggestChild,realHost, info => {
            ret = 'NETWORK_ERROR';
            if (info) { // [now_tm,expireMins,child1,child2,child3,targPubkey,rootcode,tmpPub+cipherBuf.toString()]
              let cipher = info[7];  // cipher is hex string
              let url = 'https://' + cryptoHost + '/greencard';
              wait__(fetch(url,{method:'POST',body:JSON.stringify({cipher:cipher}),referrerPolicy:'no-referrer'}),20000).then( res2 => {
                if (res2.status == 200)
                  return res2.json();
                else {
                  if (res2.status == 400)
                    return res2.text();
                  else return 'REQUEST_FAIL';
                }
              }, e => 'NETWORK_ERROR').then( data => {
                if (data && data.card) { // data.card is base64 string
                  let hexCard = rootBip.decryptGreencard(cipher.slice(0,66),data.card,data.padding);
                  if (hexCard && hexCard.slice(0,8) != '676e6364') // not 'gncd'
                    hexCard = '';
                  
                  if (hexCard) {
                    let save_tm = Math.floor((new Date()).valueOf() / 1000);
                    let expired = 0 - info[1] * 60;
                    let targ_pubkey = info[5].toString('hex');
                    let cardRec = { host,role,save_tm,expired, flag:'gncd',
                      child: info[2] + ',' + info[3] + ',' + info[4],
                      pubkey:info[5].toString('hex'), content:hexCard };
                    db.put('recent_cards',cardRec); // no waiting
                    
                    ret = { role, expired:info[1], targ_pubkey, card:hexCard };
                  }
                  else ret = 'UNKNOWN_CARD';
                }
                else if (typeof data == 'string')
                  ret = 'NETWORK_ERROR:' + data;
                // else, ret = 'NETWORK_ERROR';
                
                event.source.postMessage(prefix+JSON.stringify({id,result:ret}));
              });
            }
            else event.source.postMessage(prefix+JSON.stringify({id,result:ret}));
          });
          
          return;  // replied in previous callback
        }
      }
      
      event.source.postMessage(prefix+JSON.stringify({id,result:ret}));
    }
    
    else if (msg.cmd == 'remove_card') {
      let ret = 'NONE', cfg = null;
      let host = msg.param[0], magic = msg.param[1];
      let targHost = msg.param[2], flag = msg.param[3];
      let role = msg.param[4], child = msg.param[5];
      if ( host === NAL_WEBHOST && typeof targHost == 'string' && targHost &&
           (flag === 'pspt' || flag === 'visa' || flag === 'gncd') &&
           typeof role == 'string' && typeof child == 'string' ) {
        cfg = await (await wallet_db).get('config',host);
        if (cfg && cfg.sw_magic !== magic) cfg = null;
      }
      
      if (cfg) {
        (await wallet_db).delete('recent_cards',[targHost,flag,role,child]); // no wait
        ret = 'OK';
      }
      
      event.source.postMessage(prefix+JSON.stringify({id,result:ret}));
    }
    
    else if (msg.cmd == 'save_card') {
      let ret = 'NONE', cfg = null;
      let host = msg.param[0], magic = msg.param[1], flag = msg.param[2];
      let role = msg.param[3], child = msg.param[4], content = msg.param[5];
      let comefrom = msg.param[6] || '';
      
      if ( typeof host == 'string' && host && typeof role == 'string' && typeof child == 'string' &&
           (flag === 'pspt' || flag === 'visa' || flag === 'gncd') &&
           typeof content == 'string' && content ) {
        cfg = await (await wallet_db).get('config',host);
        if (cfg && cfg.sw_magic !== magic) cfg = null;
      }
      
      if (host == NAL_WEBHOST) {
        let targHost = msg.param[7];
        if (typeof targHost == 'string' && targHost) host = targHost;
      }
      
      if (cfg) {
        let children = child.split(',');
        children[0] = parseInt(children[0]);
        if (children[1]) children[1] = parseInt(children[1]);
        if (children[2]) children[2] = parseInt(children[2]);
        
        let info = safeCheckCard(flag,children,role?host+'+'+role:host,content);
        if (typeof info == 'string')
          ret = info
        else {
          let pubkey = info[0];
          let expired = info[1] * 60;
          let save_tm = Math.floor((new Date()).valueOf() / 1000);
          let card = {host,flag,role,child,pubkey,content,save_tm,expired:0-expired};
          if (typeof comefrom == 'string' && comefrom) card.comefrom = comefrom;
          
          await (await wallet_db).put('recent_cards',card);
          ret = 'OK';
        }
      }
      
      event.source.postMessage(prefix+JSON.stringify({id,result:ret}));
    }
    
    else if (msg.cmd == 'login_info') {
      let ret = 'NONE', cfg = null;
      let host = msg.param[0], magic = msg.param[1];
      if (typeof host == 'string' && host) {
        cfg = await (await wallet_db).get('config',host);
        if (cfg && cfg.sw_magic !== magic) cfg = null;
      }
      if (cfg) {
        let bb = cfg.login_child.split(','); // can be 'child1,child2,child3'
        let flag = bb.length >= 3? 'gncd': 'pspt';
        let child = parseInt(bb[0]);
        if (child >= 0x80000000) {
          flag = 'meta';
          child = child - 0x80000000;
        }
        else if (flag == 'gncd')
          child = 0;  // avoid showing child1,child2,child3
        
        ret = { flag, child, role:cfg.login_role, pubkey:cfg.login_pubkey,
          time:cfg.login_time, expired:cfg.login_expired };
      }
      event.source.postMessage(prefix+JSON.stringify({id,result:ret}));
    }
    
    else if (msg.cmd == 'did_logout') {
      let ret = 'NONE', cfg = null;
      let host = msg.param[0], magic = msg.param[1];
      if (typeof host == 'string' && host) {
        cfg = await (await wallet_db).get('config',host);
        if (cfg && cfg.sw_magic !== magic) cfg = null;
      }
      if (cfg) {
        cfg.login_expired = 0;
        await (await wallet_db).put('config',cfg);
        ret = 'OK';
      }
      event.source.postMessage(prefix+JSON.stringify({id,result:ret}));
    }
    
    else if (msg.cmd == 'config_acc') {
      let ret = null, tryDelay = false, bipInfo = null, psw = msg.param[0];
      if (!rootBip.hasInit()) {
        let accInfo = await (await wallet_db).get('config','account');
        if (psw && typeof psw == 'string') {
          if (accInfo) {
            bipInfo = configCheckBip(psw,accInfo);
            if (bipInfo === null) { // bipInfo is null if psw is invalid
              ret = 'WAIT_PASS';
              tryDelay = true;
            }
            else ret = 'OK';
          }
        }
        else {  // current no fixKey
          if (accInfo)
            ret = 'WAIT_PASS';
        }
        if (!ret) ret = 'NOT_READY';
      }
      else ret = 'OK';
      
      ret = JSON.stringify({id,result:ret});
      if (tryDelay)
        setTimeout(() => event.source.postMessage(prefix+ret),2000);
      else event.source.postMessage(prefix+ret);
    }
    
    else if (msg.cmd == 'ver_info') {
      let value = await (await wallet_db).get('config','ver_info');  // if failed take it as null
      event.source.postMessage(prefix+JSON.stringify({id,result:value||null}));
    }
    
    else if (msg.cmd == 'list_rsvd') {
      let ret = 'NOT_READY';
      let accInfo = await (await wallet_db).get('config','account');
      if (accInfo) {
        ret = [];
        for (let i=0; i < 9; i++) {
          let tmp = i * 10;
          tmp = Buffer.from(accInfo.rsvd_list.slice(tmp,tmp+10),'hex');
          if (tmp[4] == 0)
            tmp = tmp[3] == 0? tmp.slice(0,3): tmp.slice(0,4);
          ret.push(tmp.toString('utf-8'));
        }
      }
      event.source.postMessage(prefix+JSON.stringify({id,result:ret}));
    }
    
    else if (msg.cmd == 'check_rsvd') {
      let ret = true, rsvd = msg.param[0];
      let accInfo = await (await wallet_db).get('config','account');
      if (!accInfo || getAccountRsvd(accInfo) !== rsvd) {
        ret = false;
        rootBip.disableBip();
      }
      
      event.source.postMessage(prefix+JSON.stringify({id,result:ret}));
    }
    
    else if (msg.cmd == 'save_strategy') {
      let ret = 'OK';
      let host = msg.param[0], magic = msg.param[1], strategy = msg.param[2];
      if (typeof host == 'string' && host && strategy) {
        let cfg = await (await wallet_db).get('config',host); // cfg:{name,sw_magic,magic_tm,strategy,storage}+{...other_cfg}
        if (cfg && cfg.sw_magic === magic) {
          cfg.strategy = strategy;
          await (await wallet_db).put('config',cfg);
        }
        else ret = 'NOT_READY';
      }
      else ret = 'INVALID_ARGS';
      event.source.postMessage(prefix+JSON.stringify({id,result:ret}));
    }
    
    else if (msg.cmd == 'last_cryptohost') {
      let db = await wallet_db;
      let accInfo = await db.get('config','account');
      let crypto_host = accInfo?.crypto_host || '';
      let forceRenew = msg.param[0], expireTm = msg.param[1] || 259200;  // 259200 is 3 days
      let last_renew = accInfo.crypto_host_tm || 0;
      
      if (forceRenew || !crypto_host || (Math.floor((new Date()).valueOf()/1000) - last_renew) > expireTm)
        _renewCryptoHost(db,accInfo,now);   // no waiting
      event.source.postMessage(prefix+JSON.stringify({id,result:crypto_host,last_renew}));
    }
    
    else if (msg.cmd == 'set_ver_info') {   // must call 'save_account' at later
      let verInfo = msg.param[0];
      verInfo.name = 'ver_info';  // set keyPath
      await (await wallet_db).put('config',verInfo);
      event.source.postMessage(prefix+JSON.stringify({id,result:'OK'}));
    }
    
    else if (msg.cmd == 'add_cache') {
      caches.open('immutables').then( cache => {
        return cache.addAll(msg.param[0]);
      }).then( () => {
        event.source.postMessage(prefix+JSON.stringify({id,result:'OK'}));
      }).catch( e => {
        event.source.postMessage(prefix+JSON.stringify({id,result:e.message}));
      });
    }
    
    else if (msg.cmd == 'clear_cache') {
      caches.delete('immutables').then( succ => {
        if (succ) rootBip.disableBip();
        event.source.postMessage(prefix+JSON.stringify({id,result:(succ?'OK':'FAILED')}));
      });
    }
    
    else if (msg.cmd == 'save_account') {
      let db = await wallet_db;
      let ver_info = await db.get('config','ver_info');
      if (!ver_info) {
        event.source.postMessage(prefix+JSON.stringify({id,result:'SW_NOT_READY'}));
        return;
      }
      
      let psw = msg.param[0], accInfo = msg.param[1];
      let info = genRsvdList(accInfo.phone.slice(-4));
      accInfo.rsvd_index = info[0];
      accInfo.rsvd_list  = info[1].toString('hex');
      
      let secret = Buffer.from(accInfo.hosting_data,'hex');
      let fixKey = gen_fix_key(accInfo.phone,psw);
      let secret2 = encryptMsg(enhanceFixKey(fixKey),secret);
      accInfo.hosting_data = secret2.toString(CryptoJS.enc.Base64);
      
      let tm = Math.floor((new Date()).valueOf() / 1000);
      accInfo.name = 'account';  // set keyPath
      accInfo.regist_time = tm;
      accInfo.selfsign_no = Math.floor(Math.random() * 0x7fffffff) + 1; // not 0
      
      let fp = parseInt(accInfo.figerprint.slice(0,8),16);
      rootBip.config(secret,accInfo,fp);
      let bipInfo = rootBip.info();
      accInfo.psw_pubkey_head = bipInfo.psw_pubkey.slice(0,4);
      
      accInfo.real_manager = DEFAULT_REAL_MANAGER;
      await db.put('config',accInfo);
      REAL_MANAGER = setupRealManagers(accInfo.real_manager);
      
      ver_info.acc_type = 'restorable';
      await db.put('config',ver_info);
      
      let nalCfg = { name:NAL_WEBHOST, sw_magic:0, magic_tm:0-tm };
      await db.put('config', nalCfg);
      
      event.source.postMessage(prefix+JSON.stringify({id,result:'OK'}));
    }
    
    else if (msg.cmd == 'securebox_cfg') {  // NAL_WEBHOST only
      let nalCfg = null, host = msg.param[0], magic = msg.param[1];
      let db = await wallet_db;
      if (host === NAL_WEBHOST) {
        nalCfg = await db.get('config',host); // cfg:{name,sw_magic,magic_tm,strategy,storage}+{...other_cfg}
        if (nalCfg && nalCfg.sw_magic !== magic)
          nalCfg = null;
      }
      
      let ret, accInfo = null;
      if (nalCfg)
        accInfo = await db.get('config','account');
      if (!accInfo || !nalCfg)
        ret = 'NOT_READY';
      else ret = {figerprint:accInfo.figerprint, sort_by:nalCfg.sort_by};
      event.source.postMessage(prefix+JSON.stringify({id,result:ret}));
    }
    
    else if (msg.cmd == 'set_securebox_cfg') {  // NAL_WEBHOST only
      let accInfo = await (await wallet_db).get('config','account');
      let nalCfg = await (await wallet_db).get('config',NAL_WEBHOST);
      if (!accInfo || !nalCfg) {
        event.source.postMessage(prefix+JSON.stringify({id,result:'NOT_READY'}));
        return;
      }
      
      let ret = null, tryDelay = false;
      let psw = msg.param[0], locked = msg.param[1], sort_by = msg.param[2];
      
      if (psw && typeof psw == 'string') {
        if (!rootBip.hasInit()) {
          if (configCheckBip(psw,accInfo) === null) {  // bipInfo is null if psw mismatch
            ret = 'NEED_PASS';
            tryDelay = true;
          }
        }
        else {
          if (!verifyAccoutPass(psw,accInfo)) {
            ret = 'NEED_PASS';
            tryDelay = true;
          }
        }
        
        // if no error and current do unlock, then set securebox_cipher
        if (!ret && typeof locked == 'boolean' && !locked) {
          let pltPub = msg.param[3], pdtPub = msg.param[4];
          if (pltPub && pdtPub) {
            let fixKey = gen_fix_key(accInfo.phone,psw);
            rootBip.secureboxCipher(accInfo.crc,fixKey,pltPub,pdtPub);
          }
          else ret = 'INVALID_ARGS';
        }
      }
      
      if (ret === null) {  // no error in previous steps
        if (locked)
          rootBip.secureboxCipher(null,null); // clear securebox_cipher
        
        if (typeof sort_by == 'string') {  // try set field: sort_by
          if (sort_by != 'NAME') sort_by = 'TIME'; // only can be 'NAME' or 'TIME'
          nalCfg.sort_by = sort_by;
          await (await wallet_db).put('config', nalCfg);
        }
        
        ret = { sort_by:nalCfg.sort_by, figerprint:accInfo.figerprint,
          securebox_cipher:psw?rootBip.secureboxCipher():'' };
      }
      
      ret = JSON.stringify({id,result:ret});
      if (tryDelay)
        setTimeout(() => event.source.postMessage(prefix+ret),2000);
      else event.source.postMessage(prefix+ret);
    }
    
    else if (msg.cmd == 'sign_disabling') {
      let ret = null, tryDelay = false;
      let host = msg.param[0], magic = msg.param[1], psw = msg.param[2];
      if (host !== NAL_WEBHOST)
        ret = 'NONE';
      else if (!psw || typeof psw != 'string')
        ret = 'NEED_PASS';
      else if (!rootBip.hasInit()) {
        let accInfo = await (await wallet_db).get('config','account');
        if (accInfo) {
          bipInfo = configCheckBip(psw,accInfo);
          if (bipInfo === null) {  // bipInfo is null if psw mismatch
            ret = 'NEED_PASS';
            tryDelay = true;
          }
        }
      }
      else {
        let accInfo = await (await wallet_db).get('config','account');
        if (accInfo) {
          if (!verifyAccoutPass(psw,accInfo)) { // psw mismatch
            ret = 'NEED_PASS';
            tryDelay = true;
          }
        }
        else ret = 'NOT_READY';
      }
      
      if (ret === null && !rootBip.hasInit())
        ret = 'NOT_READY';
      
      if (!ret) {
        let now = Math.floor((new Date()).valueOf() / 1000);
        let info = rootBip.signDisabling(now);
        ret = {time:now, account:info[0], signature:info[1]};
      }
      
      ret = JSON.stringify({id,result:ret});
      if (tryDelay)
        setTimeout(() => event.source.postMessage(prefix+ret),2000);
      else event.source.postMessage(prefix+ret);
    }
    
    else if (msg.cmd == 'selfsign_pspt') {
      let ret;
      if (!rootBip.hasInit())
        ret = 'WAIT_PASS';
      else {
        let realm = msg.param[0], sessType = msg.param[1];
        let expiredTm = msg.param[2]; // expiredTm is seconds or undefined
        if (typeof realm != 'string') realm = '';
        if (typeof sessType != 'number') sessType = 1;
        
        let info = rootBip.newSelfSignPspt(sessType,realm,expiredTm);
        ret = {body:info[1].toString('hex'),signature:info[2].toString('hex'),pubkey:info[5].toString('hex')};
      }
      event.source.postMessage(prefix+JSON.stringify({id,result:ret}));
    }
    
    else if (msg.cmd == 'nick_avatar') {
      let ret = 'NONE', size = msg.param[0] || '200x200';
      let cfg = await (await wallet_db).get('config',NAL_WEBHOST);
      if (cfg) {
        let img = cfg['avatar_' + size];
        if (typeof img != 'string') img = '';
        ret = {nickname:cfg.nickname||'', avatar:img};
      }
      event.source.postMessage(prefix+JSON.stringify({id,result:ret}));
    }
    
    else if (msg.cmd == 'vdf_result') {
      let ret = Buffer.from(msg.param[0],'hex'), loop = parseInt(msg.param[1]) || 10000;
      if (vdfInstance) {
        try {
          ret = vdfInstance.generate(loop,ret,512,false); // intSizeBits=512, isPietrzak=false
        }
        catch(e) {
          console.log(e);
        }
      }
      
      ret = CreateHash('sha512').update(ret).digest().toString('hex');
      event.source.postMessage(prefix+JSON.stringify({id,result:ret}));
    }
    
    else {  // following msg.cmd for NAL_WEBHOST only
      let cfg = null, host = msg.param[0], magic = msg.param[1];
      let db = await wallet_db;
      if (host === NAL_WEBHOST) {
        cfg = await db.get('config',host); // cfg:{name,sw_magic,magic_tm,strategy,storage}+{...other_cfg}
        if (cfg && cfg.sw_magic !== magic)
          cfg = null;
      }
      
      if (msg.cmd == 'list_signature') {
        let ret = 'NONE';
        if (cfg) {
          let range = IDBKeyRange.lowerBound(0-Math.floor((new Date()).valueOf() / 1000));
          let items = await db.getAllFromIndex('sign_history','sign_tm',range,200);
          
          ret = [];
          items.forEach( item => {
            ret.push([item.id,item.child,Math.abs(item.sign_tm),item.host+'+'+item.realm]);
          });
        }
        
        event.source.postMessage(prefix+JSON.stringify({id,result:ret}));
        return;
      }
      
      else if (msg.cmd == 'get_signed_item') {
        let ret = 'NONE';
        let rowId = msg.param[2];
        if (cfg && typeof rowId == 'number') {
          let item = await db.get('sign_history',rowId);
          if (item) ret = [item.child,Math.abs(item.sign_tm),item.host+'+'+item.realm,item.pubkey,item.content,item.signature];
        }
        
        event.source.postMessage(prefix+JSON.stringify({id,result:ret}));
        return;
      }
      
      else if (msg.cmd == 'list_website') {
        let ret = 'NONE';
        if (cfg) {
          let range = IDBKeyRange.lowerBound(0-Math.floor((new Date()).valueOf() / 1000));
          let items = await db.getAllFromIndex('config','magic_tm',range,100);
          
          ret = [];
          items.forEach( item => {
            let k, roles = item.strategy?.roles || [], bb = [];
            for (k in roles) bb.push(roles[k].desc || k);
            ret.push([item.name,Math.abs(item.magic_tm),bb]);
          });
        }
        
        event.source.postMessage(prefix+JSON.stringify({id,result:ret}));
        return;
      }
      
      else if (msg.cmd == 'web_strategy') {
        let ret = 'NONE', name = msg.param[2];
        if (cfg && typeof name == 'string' && name) {
          cfg = await db.get('config',name);
          if (cfg && cfg.strategy) ret = cfg.strategy;
        }
        
        event.source.postMessage(prefix+JSON.stringify({id,result:ret}));
        return;
      }
      
      else if (msg.cmd == 'set_real_managers') {
        let ret = 'NONE', url = msg.param[2], info = msg.param[3];
        if (cfg && url && typeof url == 'string' && info) {
          if (url.indexOf('https://') == 0) url = url.slice(8).trim();
          url = url || DEFAULT_REAL_SERVER;
          
          let accInfo = await db.get('config','account');
          if (accInfo) {
            let tmp = setupRealManagers(info);
            
            accInfo.real_sp = url;
            accInfo.real_managers = info;
            await db.put('config',accInfo);
            REAL_MANAGER = tmp;
            ret = 'OK';
          }
        }
        event.source.postMessage(prefix+JSON.stringify({id,result:ret}));
        return;
      }
      
      else if (msg.cmd == 'set_acc_psw') {
        let ret = 'NONE', oldPsw = msg.param[2], newPsw = msg.param[3], rsvd = msg.param[4];
        if (cfg && typeof oldPsw == 'string' && typeof newPsw == 'string' && typeof rsvd == 'string' && rsvd.length >= 3 && rsvd.length <= 5) {
          let accInfo = await db.get('config','account');
          if (accInfo) {
            let fixKey = gen_fix_key(accInfo.phone,oldPsw);
            let secret = decryptMsg(enhanceFixKey(fixKey),accInfo.hosting_data);
            secret = Buffer.from(secret.toString(CryptoJS.enc.Hex),'hex');
            
            let passed = false;
            let pswAcc = bip32.fromPrivateKey(secret.slice(64,96),secret.slice(96,128));
            pswAcc = pswAcc.derive(0x80000000);
            if (rootBip.hasInit()) {
              let bipInfo = rootBip.info();
              if (bipInfo.psw_pubkey === pswAcc.publicKey.toString('hex'))
                passed = true;
            }
            else if (accInfo.psw_pubkey_head == pswAcc.publicKey.slice(0,2).toString('hex'))
              passed = true;
            
            if (!passed)
              ret = 'WAIT_PASS';
            else {
              fixKey = gen_fix_key(accInfo.phone,newPsw || oldPsw);
              let secret2 = encryptMsg(enhanceFixKey(fixKey),secret);
              accInfo.hosting_data = secret2.toString(CryptoJS.enc.Base64);
              
              let info = genRsvdList(rsvd);
              accInfo.rsvd_index = info[0];
              accInfo.rsvd_list  = info[1].toString('hex');
              await db.put('config',accInfo);
              
              let fp = parseInt(accInfo.figerprint.slice(0,8),16);
              rootBip.disableBip();
              rootBip.config(secret,accInfo,fp);
              ret = 'OK';
            }
          }
          else ret = 'NOT_READY';
        }
        
        event.source.postMessage(prefix+JSON.stringify({id,result:ret}));
        return;
      }
      
      if (!rootBip.hasInit()) {
        event.source.postMessage(prefix+JSON.stringify({id,result:'WAIT_PASS'}));
        return;
      }
      
      if (msg.cmd == 'acc_summary') {
        let ret = 'NONE', bipInfo = rootBip.info();
        if (cfg && bipInfo) {
          let verInfo = await db.get('config','ver_info');
          if (verInfo) {
            bipInfo.ver = verInfo.ver;
            bipInfo.install_time = verInfo.install_time;
            bipInfo.pkg_size = verInfo.pkg_size;
          }
          
          let accInfo = await db.get('config','account');
          if (accInfo) {
            bipInfo.phone = accInfo.phone;
            bipInfo.alternate_off = accInfo.alternate_off;
            bipInfo.real_sp = accInfo.real_sp || DEFAULT_REAL_SERVER;
          }
          ret = bipInfo;
        }
        
        event.source.postMessage(prefix+JSON.stringify({id,result:ret}));
      }
      
      else if (msg.cmd == 'set_selfsign') {
        let ret = 'NONE', no = msg.param[2];
        if (cfg) {
          if (typeof no == 'number' && no)
            no = Math.floor(no) & 0x7fffffff;
          else no = 0;
          if (!no) no = Math.floor(Math.random() * 0x7fffffff) + 1;  // not 0
          
          let accInfo = await db.get('config','account');
          if (accInfo) {
            pubkey = rootBip.changeSelfSign(no);
            if (pubkey) {
              accInfo.selfsign_no = no;
              await db.put('config',accInfo);
              ret = {result:'OK', selfsign_no:no, selfsign_pubkey:pubkey};
            }
          }
          else ret = 'NOT_READY';
        }
        event.source.postMessage(prefix+JSON.stringify({id,result:ret}));
      }
      
      else if (msg.cmd == 'set_nick_avatar') {
        let ret, nick = msg.param[2];
        let img200 = msg.param[3], img160 = msg.param[4], img120 = msg.param[5];
        let img80 = msg.param[6], img48 = msg.param[7], img32 = msg.param[8];
        if (typeof nick != 'string') nick = '';
        if (typeof img200 == 'string' && typeof img160 == 'string' && 
            typeof img120 == 'string' && typeof img80 == 'string' &&
            typeof img48 == 'string' && typeof img32 == 'string' ) {
          cfg.nickname = nick;
          cfg.avatar_200x200 = img200;
          cfg.avatar_160x160 = img160;
          cfg.avatar_120x120 = img120;
          cfg.avatar_80x80 = img80;
          cfg.avatar_48x48 = img48;
          cfg.avatar_32x32 = img32;
          await db.put('config',cfg);
          ret = {result:'OK'};
        }
        else ret = 'INVALID_IMAGE';
        event.source.postMessage(prefix+JSON.stringify({id,result:ret}));
      }
      
      else if (msg.cmd == 'securebox_decrypt') {
        let ret = 'DECRYPT_FAIL';
        if (cfg) {
          let ctx = rootBip.decryptSecurebox(msg.param[2]); // input should be base64 string
          ret = { content:ctx };
        }
        event.source.postMessage(prefix+JSON.stringify({id,result:ret}));
      }
      
      else if (msg.cmd == 'securebox_encrypt') {
        let ret = 'ENCRYPT_FAIL';
        if (cfg) {
          let info = rootBip.encryptSecurebox(msg.param[2]); // input should be utf-8 string
          if (info)
            ret = {size:info[0],padding:info[1],content:info[2]};
        }
        event.source.postMessage(prefix+JSON.stringify({id,result:ret}));
      }
      
      // else, ignore process
    }
  }
  catch(e) {
    console.log(e);
  }
});
