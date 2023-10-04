// Import TensorFlow.js
import * as tf from '@tensorflow/tfjs';

// Define your model URL
const modelURL = 'path/to/your/phishing-model.h5';

// Load the model
async function loadModel() {
  const model = await tf.loadLayersModel(modelURL);
  return model;
}

// Function to detect phishing
async function detectPhishing(tabId) {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  // Inject content script to extract webpage content
  chrome.scripting.executeScript({
    target: { tabId: tab.id },
    function: () => {
      // Replace this with code to extract webpage content
      // For example, you can use document.body.innerText to get the page text
      const pageContent = document.body.innerText;
      return pageContent;
    },
  },
  async (pageContent) => {
    // Check if the tab is still active and if we have content
    if (chrome.runtime.lastError || !pageContent || !pageContent[0]) {
      console.error('Error extracting webpage content:', chrome.runtime.lastError);
      return;
    }

    // Load the model
    const model = await loadModel();

    // Perform phishing detection
    const text = pageContent[0];
    const input = tf.tensor([text]);
    const prediction = model.predict(input);

    // Check the prediction result and display it in the popup
    const isPhishing = prediction.dataSync()[0] > 0.5;
    const result = isPhishing ? 'Phishing detected!' : 'No phishing detected';

    // Send the result to the popup
    chrome.action.setBadgeText({ text: isPhishing ? 'Yes' : 'No', tabId });
    chrome.action.setBadgeBackgroundColor({ color: isPhishing ? '#ff0000' : '#00ff00', tabId });
    chrome.runtime.sendMessage({ result });
  });
}

// Add a listener for the extension icon click
chrome.action.onClicked.addListener(detectPhishing);
