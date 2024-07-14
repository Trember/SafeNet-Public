function setSafeNetProxy() {
  // Define the proxy configuration
  const proxyConfig = {
    mode: 'fixed_servers',
    rules: {
      singleProxy: {
        scheme: 'http',  
        host: 'localhost',
        port: 8080
      }
      //bypassList: ['localhost', '127.0.0.1'] // Optional bypass list
    }
  };

  // Set the proxy configuration
  chrome.proxy.settings.set(
    {
      value: proxyConfig,
      scope: 'regular'
    },
    () => {
      console.log("Proxy configuration set");
    }
  );
}

function resetProxy() {
  
  // Set the proxy mode to "direct" to revert to default
  const proxyConfig = {
    mode: "direct",
  };

  chrome.proxy.settings.set(
    {
      value: proxyConfig,
      scope: "regular",
    },
    () => {
      console.log("Proxy settings reset to default");
    }
  );
}


function changeState(switchElement){
  var switchElement = event.target; // The switch that triggered the event
  if (switchElement.checked){
    setSafeNetProxy()
    console.log("Proxy server Set to SafeNet ");
  }
  else{
    resetProxy()
    console.log("Proxy server reset");
  }
}

function ProxyMain(){
  document.addEventListener("DOMContentLoaded", function() {
    // Find the switch and attach an event listener
    var switchElement = document.getElementById("safeNetStateSwitch");
    chrome.storage.sync.get("switchState", function(result) {
      if (result.switchState) {
        switchElement.checked = result.switchState; // Set the state
      }
    });
    switchElement.addEventListener("change", function() {
      changeState()
      var switchState = switchElement.checked; // Get the current state
      chrome.storage.sync.set({"switchState": switchState }); // Save the state
    });
  });
}

ProxyMain();