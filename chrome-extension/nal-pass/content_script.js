// content_script.js

const NAL_DOMAIN = 'fn-share.github.io';

document.body.setAttribute('data-nal_domain',NAL_DOMAIN);

chrome.runtime.onMessage.addListener(  function(request, sender, sendResponse) {
  if (request.cmd === 'nal_sign_what') {
    let lastSign = 0, lastRealm = '';
    let node = document.querySelector('#nbc-account');
    if (node) {
      lastSign  = parseInt(node.getAttribute('last-sign') || '0');
      lastRealm = node.getAttribute('last-realm') || '';
    }
    
    if (Math.floor((new Date()).valueOf() / 1000) - lastSign > 60)
      lastRealm = ''; // clear realm when 60 seconds later
    sendResponse(lastRealm);
  }
});
