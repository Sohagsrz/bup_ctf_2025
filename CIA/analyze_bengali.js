// Analyze the Bengali message for hidden data
const message = "Ehh asche flag nite!! joggota hoise??";

console.log('Original message:', message);
console.log('Length:', message.length);

// Try different encodings
console.log('\n=== Trying different decodings ===');

// Base64
try {
  const base64 = Buffer.from(message).toString('base64');
  console.log('Base64:', base64);
  const decoded = Buffer.from(base64, 'base64').toString();
  console.log('Base64 decoded:', decoded);
} catch (e) {}

// Hex
const hex = Buffer.from(message).toString('hex');
console.log('Hex:', hex);

// Try reversing
console.log('Reversed:', message.split('').reverse().join(''));

// Try ROT13 or other simple ciphers
function rot13(str) {
  return str.replace(/[a-zA-Z]/g, function(char) {
    const charCode = char.charCodeAt(0);
    if (charCode >= 65 && charCode <= 90) {
      return String.fromCharCode(((charCode - 65 + 13) % 26) + 65);
    } else if (charCode >= 97 && charCode <= 122) {
      return String.fromCharCode(((charCode - 97 + 13) % 26) + 97);
    }
    return char;
  });
}
console.log('ROT13:', rot13(message));

// Check if message contains flag pattern
if (message.includes('CS{') || message.includes('flag')) {
  console.log('\n*** FLAG PATTERN FOUND ***');
}

// Try URL encoding/decoding
console.log('URL encoded:', encodeURIComponent(message));
console.log('URL decoded:', decodeURIComponent(message));

