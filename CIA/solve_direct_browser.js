const puppeteer = require('puppeteer');

(async () => {
  // Try with headless: false to see what actually happens
  const browser = await puppeteer.launch({ headless: false });
  const page = await browser.newPage();
  
  page.on('response', async response => {
    if (response.url().includes('6969')) {
      const request = response.request();
      if (request.method() === 'POST') {
        const text = await response.text();
        const headers = response.headers();
        console.log('\n=== POST REQUEST DETAILS ===');
        console.log('URL:', response.url());
        console.log('Status:', response.status());
        console.log('Request Headers:', request.headers());
        console.log('Response Headers:', headers);
        console.log('Response Body:', text);
        if (text.includes('CS{')) {
          console.log('\n*** FLAG FOUND ***');
        }
      }
    }
  });
  
  page.on('dialog', async dialog => {
    const message = dialog.message();
    console.log('\n=== ALERT DIALOG ===');
    console.log('Message:', message);
    if (message.includes('CS{')) {
      console.log('\n*** FLAG FOUND IN ALERT ***');
    }
    await dialog.accept();
  });
  
  try {
    console.log('Opening page...');
    await page.goto('http://49.213.52.6:6969/', { waitUntil: 'networkidle2' });
    await new Promise(resolve => setTimeout(resolve, 3000));
    
    console.log('Clicking button...');
    await page.click('#button');
    
    // Wait longer to see all responses
    await new Promise(resolve => setTimeout(resolve, 5000));
    
    // Also try executing the fetch directly in the page context
    console.log('\nTrying direct fetch in page context...');
    const result = await page.evaluate(async () => {
      return await fetch("/", {
        method: "POST",
        body: JSON.stringify({ flagDaw: true }),
      }).then(r => r.text());
    });
    console.log('Direct fetch result:', result);
    
    // Keep browser open for a bit to see
    await new Promise(resolve => setTimeout(resolve, 5000));
    
  } catch (error) {
    console.error('Error:', error);
  } finally {
    await browser.close();
  }
})();

