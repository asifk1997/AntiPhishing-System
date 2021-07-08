let color = '#3aa757';
let key = "key";
let value = "google.com";


function check(url){
  var n1 = url.search("chrome://");
  var n2 = url.search("google");
  var n3 = url.search("phishtank");
  var n4 = url.search("binder");
  if (n1==-1 && n2==-1 && n3==-1 && n4==-1){
    return true;
  }
  return false;
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.sync.set({ color });
  chrome.storage.local.set({key: value}, function() {
    console.log('Value is set to ' + value);
  });
  console.log('Default background color set to %cgreen', `color: ${color}`);
});

chrome.tabs.onUpdated.addListener( function( tabId,  changeInfo,  tab) {
  console.log(tab.url);
  let tempUrl = tab.url;

  chrome.storage.local.get(['key'], function(result) {
  // console.log('Value currently is ' + result.key);
    currURL = result.key;
  if (currURL == tempUrl){
      // console.log(currURL);
      // console.log(tempUrl);
      console.log(99);
    }else{
      // console.log(currURL);
      // console.log(tempUrl);
      console.log(100);
      chrome.storage.local.set({key: tempUrl}, function() {
        console.log('Value is set to ' + tempUrl);
        myFunction(tempUrl);
      });
      
    }
  });

});

var lastClick = 0;
var delay = 20;

async function myFunction(url) {
  if (lastClick >= (Date.now() - delay))
    return;
  lastClick = Date.now();
  console.log("url in my function 1",url);

  console.log(check(url))
  if (check(url)){
    let finalURL = `http://127.0.0.1:5000/route?url=${url}`
    console.log("url in my function ",finalURL);
    const response = await fetch(finalURL);
    if (!response.ok){
      console.log("SOMETHING WENT WRONG")
    }
    const data = await response.json();
    console.log(data['some']);
    if (data['some'] == "phish"){
      let warn = `${url} `;
      var opt = {
        type: "basic",
        iconUrl : 'https://i.ibb.co/FX3CycL/icon48.png',
        title: "Primary Title",
        message: "Primary message to display"
      }
      // chrome.notifications.create("phishNotification", opt);

      registration.showNotification(warn, {
        body: "PHISHING ALERT",
        data: "UUID",
        icon: "https://i.ibb.co/FX3CycL/icon48.png",
        message: "phishing alert",
      })


    }
  }

}