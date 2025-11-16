const puppeteer = require('puppeteer');

(async () => {
  const browser = await puppeteer.launch({ headless: true });
  const page = await browser.newPage();
  
  page.on('dialog', async dialog => {
    const message = dialog.message();
    console.log('ALERT:', message);
    if (message.includes('CS{')) {
      console.log('*** FLAG FOUND ***');
    }
    await dialog.accept();
  });
  
  try {
    await page.goto('http://49.213.52.6:6969/');
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // Try the exact original code but intercept the request
    await page.setRequestInterception(true);
    page.on('request', request => {
      if (request.method() === 'POST') {
        // Remove Content-Type header to match original behavior
        const headers = request.headers();
        delete headers['content-type'];
        request.continue({ headers });
      } else {
        request.continue();
      }
    });
    
    // Click the button with original code
    await page.click('#button');
    await new Promise(resolve => setTimeout(resolve, 3000));
    
  } catch (error) {
    console.error('Error:', error);
  } finally {
    await browser.close();
  }
})();

