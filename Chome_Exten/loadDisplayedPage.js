async function GetPageNScript() {
  let htmlPages = ['init.html','working.html','unsafe.html']
  const result = await getStorage("userPass");
  if (result != null) {
    return htmlPages[1];
  }
  return htmlPages[0];
}

function getStorage(key) {
  return new Promise((resolve, reject) => {
    chrome.storage.local.get(key, function (result) {
      if (chrome.runtime.lastError) {
        reject(chrome.runtime.lastError);
      } else {
        // If the key does not exist, result[key] will be undefined
        resolve(result[key] !== undefined ? result[key] : null);
      }
    });
  });
}

function DisplayMain(){
  document.addEventListener("DOMContentLoaded", async () => {
    const htmlPage = await GetPageNScript();
    location.replace(htmlPage);
  });
}

DisplayMain();