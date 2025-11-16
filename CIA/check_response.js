const puppeteer = require('puppeteer');

(async () => {
  const browser = await puppeteer.launch({ headless: true });
  const page = await browser.newPage();
  
  try {
    await page.goto('http://49.213.52.6:6969/');
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Try with flagdaw (lowercase) to get the Bengali message
    const response = await page.evaluate(async () => {
      const res = await fetch("/", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ flagdaw: true }),
      });
      
      // Get all response details
      const text = await res.text();
      const headers = {};
      res.headers.forEach((value, key) => {
        headers[key] = value;
      });
      
      return {
        status: res.status,
        statusText: res.statusText,
        headers: headers,
        body: text,
        url: res.url
      };
    });
    
    console.log('Full Response Details:');
    console.log(JSON.stringify(response, null, 2));
    
    // Check if there's any hidden data
    console.log('\nChecking for hidden data...');
    console.log('Body length:', response.body.length);
    console.log('Body bytes:', Buffer.from(response.body).toString('hex'));
    
    // Try base64 decoding
    try {
      const decoded = Buffer.from(response.body, 'base64').toString();
      console.log('Base64 decoded:', decoded);
    } catch (e) {}
    
    // Check headers for clues
    console.log('\nResponse Headers:');
    Object.entries(response.headers).forEach(([key, value]) => {
      console.log(`${key}: ${value}`);
    });
    
  } catch (error) {
    console.error('Error:', error);
  } finally {
    await browser.close();
  }
})();

