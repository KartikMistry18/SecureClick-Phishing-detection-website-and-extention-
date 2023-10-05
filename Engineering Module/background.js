chrome.extension.onRequest.addListener(function(prediction){
    if (prediction == 1){
        alert("Warning: Phishing detected!!");
    }
    else if (prediction == -1){
        alert("No phishing detected / website is safe ✅");
    }
});
// chrome.extension.onRequest.addListener(function(prediction) {
//     if (prediction === 1) {
//         chrome.tabs.create({ url: "phishing_detected.html", active: true });
//     } else if (prediction === -1) {
//         chrome.tabs.create({ url: "safe_website.html", active: true });
//     }
// });
