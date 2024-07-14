async function sha256(message) {
    // encode as UTF-8
    const msgBuffer = new TextEncoder().encode(message);                    

    // hash the message
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);

    // convert ArrayBuffer to Array
    const hashArray = Array.from(new Uint8Array(hashBuffer));

    // convert bytes to hex string
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hashHex;
}

function sendMessageToBackground(message) {
    chrome.runtime.sendMessage({ type: 'send_message', content: message }, function(response) {
      console.log('Message sent to background script:', message);
    });
  }

function PasswordMain(){
    document.getElementById('passwordForm').addEventListener('submit', function(event) {
        event.preventDefault(); // Prevent the form from submitting the default way

        const formData = new FormData(event.target); // Capture form data
        var password = formData.get('password'); // Get the password field value
        sha256(password).then((encPassword) => password = encPassword);
        document.getElementById('password').value = "";
        chrome.storage.local.get("userPass", function(uPass){
            if(uPass["userPass"] != null){
                if(password == uPass["userPass"]){
                    chrome.tabs.query({ active: true, lastFocusedWindow: true }, (tabs) => {
                        if (tabs.length > 0) {
                            const currentTab = tabs[0];
                            const currentTabUrl = currentTab.url;
                            console.log("Current tab URL:", currentTabUrl);
                    
                            // Extract hostname from URL (if needed)
                            const hostname = new URL(currentTabUrl).hostname;
                            console.log("Hostname:", hostname);
                    
                            // Send message to background script with the hostname
                            sendMessageToBackground(`HTTP/1.1 200 OK Host: ${hostname} \r\n\r\n`);
                        } else {
                            console.error("No active tabs found");
                        }
                    });
                            

                    document.getElementById('result').innerHTML = `<p>Correct Password you may enter</p>`;
                }
                else{
                    document.getElementById('result').innerHTML = `<p>Incorrect Password</p>`;
                }
            }
            else{
                chrome.storage.local.set({"userPass" : password});
                location.replace('index.html');
                document.getElementById('result').innerHTML = `<p>password Setup sucssesfully</p>`;
            }});
    });
}

PasswordMain();