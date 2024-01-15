// content_script.js

const NAL_DOMAIN = 'fn-share.github.io';

document.body.setAttribute('data-nal_domain',NAL_DOMAIN);

window.addEventListener('message', function(ev) {
  if (ev.source === window && typeof ev.data == 'string' && ev.data.slice(0,8) === 'NAL_REQ:') {
    chrome.runtime.sendMessage(ev.data.slice(8), res => {  // slice(8): {id,cmd,param}
      if (typeof res != 'string') res = JSON.stringify(res);
      window.postMessage('NAL_RPY:'+res);
    });
  }
});
