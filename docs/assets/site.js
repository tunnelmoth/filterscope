(function(){
  var REPO="tunnelmoth/filterscope", base="https://github.com/"+REPO+"/releases/latest/download/";
  function setLang(l){document.documentElement.lang=l;document.getElementById('lang-en').classList.toggle('on',l==='en');document.getElementById('lang-tr').classList.toggle('on',l==='tr');try{localStorage.setItem('fs-lang',l)}catch(e){}}
  window.setLang=setLang;
  document.getElementById('lang-en').addEventListener('click',function(){setLang('en')});
  document.getElementById('lang-tr').addEventListener('click',function(){setLang('tr')});
  // language: ?lang=tr or #tr in the URL wins, then the saved choice, then the browser language
  var q=(location.search.match(/[?&]lang=(en|tr)/)||[])[1]||(location.hash==='#tr'?'tr':location.hash==='#en'?'en':null);
  if(q)setLang(q);else{try{var s=localStorage.getItem('fs-lang');if(s)setLang(s);else if((navigator.language||'').toLowerCase().startsWith('tr'))setLang('tr');}catch(e){}}
  // highlight the button for this device
  var ua=navigator.userAgent, plat=navigator.platform||"", os=null;
  if(/Android/i.test(ua))os="android"; else if(/Windows/i.test(ua))os="windows";
  else if(/Mac/i.test(plat)&&!/iPhone|iPad/.test(ua))os="mac"; else if(/Linux/i.test(plat))os="linux";
  if(os){var b=document.querySelector('.btn.plat[data-os="'+os+'"]');if(b){b.classList.add('here');var row=document.getElementById('cta-row');row.insertBefore(b,row.firstChild);}}
  // fill versioned asset names (setup exe, apk) from the latest release
  fetch("https://api.github.com/repos/"+REPO+"/releases/latest").then(function(r){return r.json()}).then(function(rel){
    if(!rel||!rel.assets)return;
    var v=rel.tag_name||"";document.getElementById('ver').textContent=v;document.getElementById('ver2').textContent=v;
    rel.assets.forEach(function(a){
      document.querySelectorAll('a[data-asset]').forEach(function(el){
        var key=el.getAttribute('data-asset');
        if(a.name.indexOf(key)!==-1){el.href=a.browser_download_url;if(el.classList.contains('dl'))el.textContent=a.name;}
      });
    });
  }).catch(function(){});
})();
