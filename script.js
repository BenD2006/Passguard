// --- Global Variables ---
var credentialsToStore = [];
var passwordToStoreEncryptIV;
var passwordToStoreEncrypt;

document.addEventListener("DOMContentLoaded", () => {
    displayPasswords();
});

// --- Event Listeners ---
window.onload = function() {
    // This is a placeholder for a real login check.
    // In a real app, you'd check a secure token, not just a localStorage item.
    // For this demo, we assume the user is "logged in" to see the dashboard.
    // checkLogin(); 
    displayPasswords();
};

// This would log a user out if they close the tab.
window.onbeforeunload = function(event) {
    if (!event || event.type === "unload") {
        // In a real app, you might not want to automatically log out.
        // localStorage.removeItem("loggedIn");
    }
};

// --- Core Functions ---

function checkLogin() {
    const LoggedIn = localStorage.getItem('loggedIn');
    if (LoggedIn === null) {
        // window.location.href = "index.html";
        console.log("User not logged in. Redirect would happen here.");
    }
}

function logout() {
    localStorage.removeItem("loggedIn");
    window.location.href = "index.html";
}

function generatePassword() {
    const charsToUse = {
        lower: "abcdefghijklmnopqrstuvwxyz",
        upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        numbers: "0123456789",
        symbols: "!£$%^&*()[]{}'@#~;:/?",
    };

    let combinedChars = "";
    if (document.getElementById("lchar").checked) combinedChars += charsToUse.lower;
    if (document.getElementById("uchar").checked) combinedChars += charsToUse.upper;
    if (document.getElementById("num").checked) combinedChars += charsToUse.numbers;
    if (document.getElementById("sym").checked) combinedChars += charsToUse.symbols;

    const passwordLength = parseInt(document.getElementById("numofchar").value, 10);

    if (passwordLength < 8 || passwordLength > 100) {
        alert("Password length must be between 8 and 100 characters.");
        return;
    }
    if (combinedChars === "") {
        alert("Please select at least one character type.");
        return;
    }

    let generatedPassword = "";
    for (let i = 0; i < passwordLength; i++) {
        const randomIndex = Math.floor(Math.random() * combinedChars.length);
        generatedPassword += combinedChars[randomIndex];
    }

    const passwordGenElement = document.getElementById("passwordgen");
    passwordGenElement.textContent = generatedPassword;
    passwordGenElement.style.display = "block";
}

async function savePassword() {
    const websiteName = document.getElementById("webpage").value.trim();
    const userName = document.getElementById("username").value.trim();
    const passwordToStore = document.getElementById("password").value;

    if (!websiteName || !userName || !passwordToStore) {
        alert("Website, Username, and Password fields cannot be empty.");
        return;
    }

    credentialsToStore = [];
    const salt = await callEncryption(passwordToStore, websiteName);
    
    credentialsToStore.push({
        websiteName: websiteName,
        userName: userName,
        iv: passwordToStoreEncryptIV,
        encryptPass: passwordToStoreEncrypt,
        salt: salt
    });
    
    localStorage.setItem(websiteName, JSON.stringify(credentialsToStore));
    alert("Password successfully stored!");
    displayPasswords();
    // Clear form
    document.getElementById("webpage").value = '';
    document.getElementById("username").value = '';
    document.getElementById("password").value = '';
}

function deletePassword() {
    const websiteName = document.getElementById("deletewebpage").value.trim();
    if (!websiteName) {
        alert("Please enter a website name to delete.");
        return;
    }

    if (localStorage.getItem(websiteName) != null) {
        if (confirm(`Are you sure you want to delete the password for "${websiteName}"?`)) {
            localStorage.removeItem(websiteName);
            alert("Password deleted.");
            displayPasswords();
            document.getElementById("deletewebpage").value = '';
        }
    } else {
        alert("No password stored for that website name.");
    }
}

async function editPassword() {
    const websiteName = document.getElementById("editwebpage").value;
    const usernameEdit = document.getElementById("editusername").value;
    const passwordEdit = document.getElementById("editpassword").value;

    let passwordStoredToEdit = localStorage.getItem(websiteName);
    if (!passwordStoredToEdit) {
        alert("No password stored for this website.");
        return;
    }

    let passwordStoredUnstring = JSON.parse(passwordStoredToEdit);

    passwordStoredUnstring[0].userName = usernameEdit;

    // Only re-encrypt if the password has changed
    if (passwordEdit) {
         // *** FIX: A new salt must be generated and stored when the password changes ***
         const newSalt = await callEncryption(passwordEdit, websiteName);
         passwordStoredUnstring[0].iv = passwordToStoreEncryptIV;
         passwordStoredUnstring[0].encryptPass = passwordToStoreEncrypt;
         passwordStoredUnstring[0].salt = newSalt; // Store the new salt
    }
    
    localStorage.setItem(websiteName, JSON.stringify(passwordStoredUnstring));
    alert("Password successfully updated.");
    document.getElementById('editpasswordmodal').style.display = 'none';
    displayPasswords();
}

function clearStorage() {
    if (confirm("Are you sure you want to delete ALL stored passwords? This action cannot be undone.")) {
        localStorage.clear();
        displayPasswords();
        alert("All passwords have been deleted.");
    }
}

function changeBGColour(colour) {
    document.body.style.backgroundColor = colour;
}

async function getPasswords() {
    let passwordsList = [];
    for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key === "loginUser" || key === "loggedIn") {
            continue; // Skip non-password entries
        }
        const data = localStorage.getItem(key);
        try {
            const dataParsed = JSON.parse(data);
            if (Array.isArray(dataParsed) && dataParsed[0]) {
                 const decryptedPassword = await callDecryption(dataParsed[0].websiteName, dataParsed[0].salt);
                 passwordsList.push({
                    websiteName: dataParsed[0].websiteName,
                    userName: dataParsed[0].userName,
                    password: decryptedPassword,
                });
            }
        } catch (error) {
            console.warn(`Skipping invalid entry for key: ${key}`, error);
        }
    }
    return passwordsList;
}

async function displayPasswords() {
    const passwordTableBody = document.getElementById('passwordTableBody');
    passwordTableBody.innerHTML = ''; // Clear existing rows

    const passwords = await getPasswords();

    if (passwords.length === 0) {
        const row = document.createElement('tr');
        row.innerHTML = `<td colspan="3">No passwords stored yet.</td>`;
        passwordTableBody.appendChild(row);
        return;
    }

    passwords.forEach(password => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${password.websiteName}</td>
            <td>${password.userName}</td>
            <td data-password="${password.password}" data-visible="false">••••••••</td>
        `;
        row.addEventListener('click', () => {
            document.getElementById("editpasswordmodal").style.display = "flex";
            document.getElementById("editwebpage").value = password.websiteName;
            document.getElementById("editusername").value = password.userName;
            // Leave password blank for security, user must re-type to change.
            document.getElementById("editpassword").value = ""; 
            document.getElementById("editpassword").placeholder = "Enter new password (optional)";
        });
        passwordTableBody.appendChild(row);
    });
}

function togglePasswordVisibility() {
    const passwordCells = document.querySelectorAll('#passwordTableBody td:nth-child(3)');
    passwordCells.forEach(cell => {
        if (cell.dataset.password) { // Check if there is a password to toggle
            if (cell.dataset.visible === "true") {
                cell.textContent = "••••••••";
                cell.dataset.visible = "false";
            } else {
                cell.textContent = cell.dataset.password;
                cell.dataset.visible = "true";
            }
        }
    });
}

async function searchPassword() {
    const query = document.getElementById("passwordSearch").value.toLowerCase().trim();
    const resultsContainer = document.getElementById("searchResults");
    resultsContainer.innerHTML = "";

    if (query === "") {
        closeSearchResults();
        return;
    }
    
    const passwords = await getPasswords();
    const filteredResults = passwords.filter(pw =>
        pw.websiteName.toLowerCase().includes(query) || 
        pw.userName.toLowerCase().includes(query)
    );

    if (filteredResults.length > 0) {
        document.getElementById("searchResultsModal").style.display = "flex";
        filteredResults.forEach(password => {
            const resultItem = document.createElement("div");
            resultItem.innerHTML = `<p><strong>${password.websiteName}</strong><br>Username: ${password.userName}<br>Password: ${password.password}</p>`;
            resultsContainer.appendChild(resultItem);
        });
    } else {
        resultsContainer.innerHTML = "<p>No matches found.</p>";
        document.getElementById("searchResultsModal").style.display = "flex";
    }
}

function closeSearchResults() {
    document.getElementById("searchResultsModal").style.display = "none";
}

function checkPasswordStrength() {
    const password = document.getElementById("passwordCheck").value;
    const power = document.getElementById("power-point");
    let point = 0;
    const widthPower = ["1%", "25%", "50%", "75%", "100%"];
    const colorPower = ["#D73F40", "#DC6551", "#F2B84F", "#BDE952", "#3ba62f"];

    if (password.length >= 8) {
        point++;
        if (/[a-z]/.test(password) && /[A-Z]/.test(password)) point++;
        if (/[0-9]/.test(password)) point++;
        if (/[^0-9a-zA-Z]/.test(password)) point++;
    } else if (password.length > 0) {
        point = 1;
    } else {
        point = 0;
    }

    power.style.width = widthPower[point] || "1%";
    power.style.backgroundColor = colorPower[point] || "#D73F40";
}

// --- Encryption/Decryption Functions (Simplified for Demo) ---
// NOTE: Web Crypto API is complex. This is a simplified implementation.
// In a real-world scenario, robust error handling and key management are critical.

async function keyDeriveFromPassword(password, salt) {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        "raw", encoder.encode(password), "PBKDF2", false, ["deriveBits", "deriveKey"]
    );
    return crypto.subtle.deriveKey(
        { name: "PBKDF2", salt: salt, iterations: 100000, hash: "SHA-256" },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

async function encryptAndStore(key, data_to_encrypt) {
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encryptedData = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv }, key, new TextEncoder().encode(data_to_encrypt)
    );
    passwordToStoreEncryptIV = Array.from(iv);
    passwordToStoreEncrypt = Array.from(new Uint8Array(encryptedData));
}

async function decryptFromStore(key, iv, encrypted_data) {
    try {
        const decrypted_data = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv }, key, encrypted_data
        );
        return new TextDecoder().decode(decrypted_data);
    } catch (e) {
        console.error("Decryption failed:", e);
        return "DECRYPTION FAILED";
    }
}

async function callEncryption(data, website) {
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    // Using the website name as part of the password for key derivation is not standard.
    // A better approach would be to use a master password. For this demo, we'll use the website name.
    const key = await keyDeriveFromPassword(website, salt);
    await encryptAndStore(key, data);
    return Array.from(salt);
}

async function callDecryption(website, saltArray) {
    const salt = new Uint8Array(saltArray);
    const key = await keyDeriveFromPassword(website, salt);
    
    const encrypted_data_string = localStorage.getItem(website);
    const encrypted_data = JSON.parse(encrypted_data_string);
    const iv = new Uint8Array(encrypted_data[0].iv);
    const encrypted_array = new Uint8Array(encrypted_data[0].encryptPass);

    return await decryptFromStore(key, iv, encrypted_array);
}
