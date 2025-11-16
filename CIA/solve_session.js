const puppeteer = require('puppeteer');

(async () => {
  const browser = await puppeteer.launch({ headless: true });
  const page = await browser.newPage();
  
  page.on('response', async response => {
    if (response.url().includes('6969')) {
      const text = await response.text();
      if (response.request().method() === 'POST') {
        console.log('POST Response Status:', response.status());
        console.log('POST Response:', text);
        if (text.includes('CS{')) {
          console.log('*** FLAG FOUND ***');
        }
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
    // First, visit the page normally
    console.log('Visiting page...');
    await page.goto('http://49.213.52.6:6969/');
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Check cookies
    const cookies = await page.cookies();
    console.log('Cookies:', cookies);
    
    // Get all headers that the page would send
    const headers = await page.evaluate(() => {
      return {
        userAgent: navigator.userAgent,
        language: navigator.language,
        platform: navigator.platform
      };
    });
    console.log('Browser info:', headers);
    
    // Now try the exact original code
    console.log('\nTrying original code...');
    await page.click('#button');
    await new Promise(resolve => setTimeout(resolve, 3000));
    
    // Also try with a small delay between GET and POST
    console.log('\nTrying with delay...');
    await page.goto('http://49.213.52.6:6969/');
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    const result = await page.evaluate(async () => {
      // Wait a bit
      await new Promise(r => setTimeout(r, 500));
      const res = await fetch("/", {
        method: "POST",
        body: JSON.stringify({ flagDaw: true }),
      });
      return await res.text();
    });
    console.log('Delayed result:', result);
    
  } catch (error) {
    console.error('Error:', error);
  } finally {
    await browser.close();
  }
})();

