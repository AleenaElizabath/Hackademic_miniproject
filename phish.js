async function checkEmail(emailFeatures) {
  const res = await fetch("http://127.0.0.1:5000/predict_phish", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ features: emailFeatures })
  });
  const data = await res.json();
  return data.prediction; // 0 = safe, 1 = phishing
}

// Example usage
const features = [0, 1, 0, 1, 0]; // extracted from email (dummy example)
checkEmail(features).then(prediction => {
  if (prediction === 1) {
    alert("⚠️ This looks like a phishing email!");
  } else {
    alert("✅ This email seems safe.");
  }
});
