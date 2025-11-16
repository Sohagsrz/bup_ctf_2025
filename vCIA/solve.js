const puppeteer = require('puppeteer');

(async () => {
  const browser = await puppeteer.launch({ headless: true });
  const page = await browser.newPage();
  
  try {
    // Navigate to the page
    await page.goto('http://49.213.52.6:6969/');
    
    // Set up a listener for the alert
    page.on('dialog', async dialog => {
      console.log('Alert:', dialog.message());
      await dialog.accept();
    });
    
    // Click the button
    await page.click('#button');
    
    // Wait a bit for the alert
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Also try to get the response directly
    const response = await page.evaluate(async () => {
      const res = await fetch('/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ flagDaw: true })
      });
      return await res.text();
    });
    
    console.log('Direct fetch response:', response);
    
  } catch (error) {
    console.error('Error:', error);
  } finally {
    await browser.close();
  }
})();

