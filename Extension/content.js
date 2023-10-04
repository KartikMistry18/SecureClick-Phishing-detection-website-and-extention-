
// Function to extract webpage content
function extractWebpageContent() {
    const pageContent = document.body.innerText;
    return pageContent;
  }
  
  // Send the extracted content to the background script for further processing
  chrome.runtime.sendMessage({ content: extractWebpageContent() }, (response) => {
    if (response.result) {
      // Handle the phishing detection result here
      if (response.result === 'Phishing detected!') {
        // Replace or customize this part to display a warning to the user
        console.warn('Phishing detected on this page!');
      }
    }
  });