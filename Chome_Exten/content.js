// Function to check if the current page matches the black HTML page
function detectBlackPage() {
  // Check for the unique identifier in the meta tag
  const metaTag = document.querySelector('meta[name="identifier"]');
  const isBlackPage = metaTag && metaTag.getAttribute('content') === 'my-black-page';

  if (isBlackPage) {
    // Send message to extension
    chrome.runtime.sendMessage({ action: 'blackPageDetected', url: window.location.href });
  }
}

// Run the detection function
detectBlackPage();
