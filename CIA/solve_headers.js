const puppeteer = require('puppeteer');

(async () => {
  const browser = await puppeteer.launch({ headless: true });
  const page = await browser.newPage();
  
  page.on('response', async response => {
    if (response.url().includes('6969') && response.request().method() === 'POST') {
      const text = await response.text();
      console.log('POST Response:', text);
      if (text.includes('CS{')) {
        console.log('*** FLAG FOUND ***');
      }
    }
  });
  
  try {
    await page.goto('http://49.213.52.6:6969/');
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Try with all the headers that a real browser would send
    const result = await page.evaluate(async () => {
      const res = await fetch("/", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Accept": "*/*",
          "Accept-Language": "en-US,en;q=0.9",
          "Cache-Control": "no-cache",
          "Pragma": "no-cache",
          "Sec-Fetch-Dest": "empty",
          "Sec-Fetch-Mode": "cors",
          "Sec-Fetch-Site": "same-origin"
        },
        body: JSON.stringify({ flagDaw: true }),
        credentials: "same-origin",
        referrer: window.location.href,
        referrerPolicy: "strict-origin-when-cross-origin"
      });
      return await res.text();
    });
    console.log('Result with all headers:', result);
    
    // Try modifying the button's onclick to use a different approach
    await page.evaluate(() => {
      const button = document.getElementById('button');
      const newButton = button.cloneNode(true);
      button.parentNode.replaceChild(newButton, button);
      
      newButton.addEventListener("click", async () => {
        // Try using XMLHttpRequest instead of fetch
        return new Promise((resolve) => {
          const xhr = new XMLHttpRequest();
          xhr.open("POST", "/");
          xhr.setRequestHeader("Content-Type", "application/json");
          xhr.onload = () => {
            alert(xhr.responseText);
            resolve(xhr.responseText);
          };
          xhr.send(JSON.stringify({ flagDaw: true }));
        });
      });
    });
    
    console.log('\nTrying with XMLHttpRequest...');
    await page.click('#button');
    await new Promise(resolve => setTimeout(resolve, 3000));
    
  } catch (error) {
    console.error('Error:', error);
  } finally {
    await browser.close();
  }
})();

