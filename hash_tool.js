const bcrypt = require('bcryptjs');

// Change this to whatever password you want to hash
const passwordToHash = "123456"; 

async function generate() {
    console.log("---------------------------------");
    console.log("🔐 Password Hashing Utility");
    console.log("---------------------------------");
    
    const saltRounds = 10;
    const hash = await bcrypt.hash(passwordToHash, saltRounds);
    
    console.log(`Original Password: ${passwordToHash}`);
    console.log(`Copy this Hash:${hash}`);
    console.log("---------------------------------");
    console.log("🚀 Manual Step: Paste this hash into your Firebase 'password' field.");
}

generate();