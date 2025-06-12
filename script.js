var passwordInputted = document.getElementById("userpass");
var lengthOfPass = document.getElementById("length");
var lowercaseLetter = document.getElementById("lowercase");
var uppercaseLetter = document.getElementById("uppercase");
var numberUsed = document.getElementById("number");
var credentialsToStore = [];
var passwordToStoreEncryptIV;
var passwordToStoreEncrypt;

onload = function() {
    // Check if the user is logged in when the page loads
    if (localStorage.getItem("loggedIn") === "true") {
        document.getElementById("loginWindow").style.display = "none";
        document.getElementById("mainContainer").style.display = "flex";
        document.getElementById("menuRight").style.display = "flex";
        displayPasswords();
    } else {
        document.getElementById("loginWindow").style.display = "flex";
        document.getElementById("mainContainer").style.display = "none";
        document.getElementById("menuRight").style.display = "none";
    }
}
// Function created to make the new account window and check if user account already exists
function createAccountWindow() {
    if (localStorage.getItem("loginUser") != ''){
        document.getElementById("createAccount").style.display = "flex";
    } else {
        alert("User already created");
    }
}

// Asynchronous function used to create a new account and get all data from the user, then stores to local storage.
async function createAccount() {
    document.getElementById("loginWindow").style.display = "none";
    let usernameInputted = document.getElementById("login-username-new").value;
    let passwordInputted = document.getElementById("login-password-new").value;
    if (passwordInputted.length < 8) {
        alert("Password Doesn't Meet Requirements");
        document.getElementById("loginWindow").style.display = "flex";
        return;
       
    }
    let q1ans = document.getElementById("sq1-answer").value;
    let q2ans = document.getElementById("sq2-answer").value;
    let loginCredentials = [];
    await callEncryption(passwordInputted, "loginUser");
    let pIv = passwordToStoreEncryptIV;
    let pEnc = passwordToStoreEncrypt;
    loginCredentials.push({websiteName:"loginUser", userName:usernameInputted, iv:pIv, encryptPass:pEnc, q1ans:q1ans, q2ans:q2ans});
    localStorage.setItem("loginUser", JSON.stringify(loginCredentials));
    document.getElementById("createAccount").style.display = "none";
    document.getElementById("loginWindow").style.display = "flex";
}

// Function used to authenticate the user into the site using the entered username and password, and the local storage data.
async function login() {
    var usernameInputted = document.getElementById("login-username").value;
    var passwordInputted = document.getElementById("login-password").value;
    var savedloginData = JSON.parse(localStorage.getItem("loginUser"))
    let savedPasswordEncrypt = await callDecryption("loginUser") 
    let savedUsername = savedloginData[0].userName;
    let usernameCorrect = false;
    let passwordCorrect = false;
    if (usernameInputted === savedUsername) {
        usernameCorrect = true;
    }
    if (passwordInputted === savedPasswordEncrypt) {
        passwordCorrect = true;
    }
    if (usernameCorrect == true && passwordCorrect == true) {
        localStorage.setItem("loggedIn", "true");
        document.getElementById("loginWindow").style.display = "none";
        document.getElementById("mainContainer").style.display = "flex";
        document.getElementById("menuRight").style.display = "flex";
        displayPasswords();
    } else {
        alert("Either your username or password is incorrect, please try again");
    }
}

// Function used to log out the user by clearing the screen and showing the log in page
function logout() {
    localStorage.setItem("loggedIn", "false");
    document.getElementById('loginWindow').style.display='flex';
    document.getElementById('menuRight').style.display = 'none';
}

// Function used if the user forgets their password, asking for the security question answers and setting a new password
function forgotPassword() {
    let resetFlag = false;
    let q1ansNew = document.getElementById("sq1-answer-fg").value;
    let q2ansNew = document.getElementById("sq2-answer-fg").value;
    let credentials = localStorage.getItem("loginUser");
    let unstringCredentials = JSON.parse(credentials);
    if (credentials == null) {
        alert("No user created");
        document.getElementById("forgotpassword").style.display = "none";
        return;
    }
    let q1ans = unstringCredentials[0].q1ans;
    let q2ans = unstringCredentials[0].q2ans;
    if (q1ansNew == q1ans && q2ansNew == q2ans) {
        resetFlag = true;
    } else {
        alert("Wrong answers provided");
    }
    if (resetFlag == true) {
        document.getElementById("questions").style.display = "none";
        document.getElementById("passreset").style.display = "flex";
    }

}

// Function called using the reset password function to create a new password for the account
async function newPassword() {
    let passwordInputtedNew = document.getElementById("newPass").value;
    let credentials = localStorage.getItem("loginUser");
    let unstringCredentials = JSON.parse(credentials);
    await callEncryption(passwordInputtedNew,"loginUser");
    unstringCredentials[0].iv = passwordToStoreEncryptIV;
    unstringCredentials[0].encryptPass =  passwordToStoreEncrypt;
    localStorage.setItem("loginUser", JSON.stringify(unstringCredentials));
    document.getElementById("passreset").style.display = "none";
    document.getElementById("loginWindow").style.display = "none";
    document.getElementById("forgotpassword").style.display = "none";
    document.getElementById("mainContainer").style.display = "block";
    document.getElementById("menuRight").style.display = "flex";
    

}
// Function used to generate the user a new password using the requirements set
function generatePassword() {
    const baseChars = "abcdefghijklmnopqrstuvwxyz";
    var charsToUse = "abcdefghijklmnopqrstuvwxyz";
    const uppercaseCharacters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const numericCharacters = "0123456789";
    const symbolCharacters = "!£$%^&*()[]{}'@#~;:/?";
    var passwordLength = document.getElementById("numofchar").value;
    var specialChar = document.getElementById("sym").checked;
    var lowercaseLetter = document.getElementById("lchar").checked;
    var upChar = document.getElementById("uchar").checked;
    var numbers = document.getElementById("num").checked;
    var generatedPassword = "";
    if (passwordLength <8 || passwordLength >=100) {
        alert("Password Length is Invalid or Insecure"); 
    } else {
        if (lowercaseLetter == false && upChar == false && numbers == false && specialChar == false) {
            alert("Please select at least one option");
        }
        if (lowercaseLetter == false) {
            var charsToUse = ''
        }
        if (specialChar == true) {
            charsToUse += symbolCharacters;
        }
        if (upChar == true) {
            charsToUse += uppercaseCharacters;
        }
        if (numbers == true) {
            charsToUse += numericCharacters;
        }
        for (i=0;i < passwordLength; i++) {
            charToAdd = charsToUse[Math.floor(Math.random() * charsToUse.length)];
            generatedPassword += charToAdd;
        }
        document.getElementById("passwordgen").innerHTML = "password: " + generatedPassword;
        document.getElementById("passwordgen").style.display = "flex";
        charsToUse = "abcdefghijklmnopqrstuvwxyz";
    }
}

// Function used to save one of the users passwords into local storage
async function savePassword() {
    var websiteName = document.getElementById("webpage").value;
    var userName = document.getElementById("username").value;
    var passwordToStore = document.getElementById("password").value;
    credentialsToStore = [];
    await callEncryption(passwordToStore, websiteName);
    credentialsToStore.push({websiteName:websiteName, userName:userName, iv:passwordToStoreEncryptIV, encryptPass: passwordToStoreEncrypt});
    localStorage.setItem(websiteName, JSON.stringify(credentialsToStore));
    alert("Password Sucessfully Stored");
    displayPasswords();
}

// Function used to delete a password from local storage
function deletePassword() {
    var websiteName = document.getElementById("deletewebpage").value;
    if (localStorage.getItem(websiteName) != null) {
        localStorage.removeItem(websiteName);
        alert("Password Deleted");
        displayPasswords();
    } else {
        alert("Not a valid username for a password that is stored");
    }
}

// Function to edit a password of the users choice in local storage
async function editPassword() {
    let websiteName = document.getElementById("editwebpage").value;
    let usernameEdit = document.getElementById("editusername").value;
    let passwordEdit = document.getElementById("editpassword").value;
    let passwordStoredToEdit = localStorage.getItem(websiteName);
    let passwordStoredUnstring;

    if (!passwordStoredToEdit) {
        alert("No password stored for this website.");
    }
    try {
        passwordStoredUnstring = JSON.parse(passwordStoredToEdit);
    } catch (e) {
        alert("Error with password data.");
    }
    if (!Array.isArray(passwordStoredUnstring) || !passwordStoredUnstring[0] || typeof passwordStoredUnstring[0] !== 'object') {
        alert("Stored data is not in the expected format.");
    }

    if (usernameEdit === "" && passwordEdit === "") {
        alert("No Changes Have Been Made");
    }

    if (usernameEdit !== "") {
        passwordStoredUnstring[0].userName = usernameEdit;
    }

    if (passwordEdit !== "") {
        await callEncryption(passwordEdit, websiteName);
        passwordStoredUnstring[0].iv = passwordToStoreEncryptIV;
        passwordStoredUnstring[0].encryptPass = passwordToStoreEncrypt;
    }
    passwordStoredToEdit = JSON.stringify(passwordStoredUnstring);
    localStorage.setItem(websiteName, passwordStoredToEdit);
    alert("Sucessfully Edited");
    if (document.getElementById("editpasswordmodal").style.display === "block") {
        document.getElementById("editpasswordmodal").style.display = "none";
        document.getElementById("mainContainer").style.display = "flex";

    }
    displayPasswords();
}

// Small function used to clear all data in local storage
function clearStorage() {
    localStorage.clear();
    displayPasswords();
}

// Function used to change the background colour
function changeBGColour(colour) {
    document.body.style.background = colour;
}

// Function to derive the key
async function keyDeriveFromPassword(password) {
    const buffer = new TextEncoder().encode(password);
    const salt = new TextEncoder().encode("mysalt");
    const keyDerive = await crypto.subtle.importKey(
        "raw",
        buffer,
        "PBKDF2",
        false,
        ["deriveBits", "deriveKey"]
    );

    const key = await crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations:10000,
            hash: "SHA-256"
        },
        keyDerive,
        {
            name: "AES-GCM",
            length:256
        },
        true,
        ["encrypt", "decrypt"]
    );

    return key;
}

// Function used to encrypt the data
async function encryptAndStore(encryption_key, data_to_encrypt, websiteName) {
    var data_encoded = new TextEncoder()
    var data = data_encoded.encode(data_to_encrypt);
    var iv = window.crypto.getRandomValues(new Uint8Array(12));
    var data_encrypted = await crypto.subtle.encrypt(
        {
            name:"AES-GCM",
            iv:iv,
        },
        encryption_key,
        data
    );
    passwordToStoreEncryptIV = Array.from(iv);
    passwordToStoreEncrypt = Array.from(new Uint8Array(data_encrypted))
}

// Function used to decrypt the data
async function decryptFromStore(key, website) {
    try {
        var encrypted_data_string = localStorage.getItem(website);
        if (!encrypted_data_string) {
            throw new Error ("NO DATA");
        }
        var encrypted_data = JSON.parse(encrypted_data_string);
        var ivDecrypt = new Uint8Array(encrypted_data[0].iv);
        var encrypted_array = new Uint8Array(encrypted_data[0].encryptPass);
        var decrypted_data = await crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: ivDecrypt,
            },
            key,
            encrypted_array
        );

        const decoder = new TextDecoder();
        let decodedData =  decoder.decode(decrypted_data);
        return decodedData;
    } catch (error) {
        console.error("ERROR OCCURED ", error);
    }
}


async function callEncryption(data, website) {
    var data = data;
    var website = website;
    var key = await keyDeriveFromPassword(website);
    await encryptAndStore(key, data, website);
}

async function callDecryption(website) {
    var website = website;
    var key = await keyDeriveFromPassword(website);
    var decrypted_pass = await decryptFromStore(key, website);
    return decrypted_pass;
}



async function getPasswords() {
    var passwordsList = [];
    for (i = 0; i <= localStorage.length - 1; i++) {
        if (localStorage.key(i) === "loginUser") {
            continue; // Skip the loginUser entry
        }
        var key = localStorage.key(i);
        var data = localStorage.getItem(key);

        try {
            var dataParsed = JSON.parse(data);

            // Ensure the data follows the expected format
            if (
                Array.isArray(dataParsed) &&
                dataParsed[0] &&
                typeof dataParsed[0] === "object" &&
                "websiteName" in dataParsed[0] &&
                "userName" in dataParsed[0] &&
                "iv" in dataParsed[0] &&
                "encryptPass" in dataParsed[0]
            ) {
                passwordsList.push({
                    websiteName: dataParsed[0].websiteName,
                    userName: dataParsed[0].userName,
                    password: await callDecryption(dataParsed[0].websiteName)
                });
            }
        } catch (error) {
            console.warn(`Skipping invalid entry for key: ${key}`, error);
        }
    }
    return passwordsList;
}

function togglePasswordVisibility() {
    const passwordCells = document.querySelectorAll('#passwordTableBody td:nth-child(3)');
    passwordCells.forEach(cell => {
        if (cell.dataset.visible === "true") {
            cell.textContent = ".................";
            cell.dataset.visible = "false";
        } else {
            cell.textContent = cell.dataset.password;
            cell.dataset.visible = "true";
        }
    });
}

// Modify displayPasswords to store the actual password in a data attribute
async function displayPasswords() {
    const passwordTableBody = document.getElementById('passwordTableBody');
    passwordTableBody.innerHTML = ''; // Clear existing rows

    const passwords = await getPasswords();

    passwords.forEach(password => {
        const row = document.createElement('tr');

        row.innerHTML = `
            <td style="border: 1px solid black; padding: 8px;">${password.websiteName}</td>
            <td style="border: 1px solid black; padding: 8px;">${password.userName}</td>
            <td style="border: 1px solid black; padding: 8px;" data-password="${password.password}" data-visible="false">••••••••</td>
        `;

        row.addEventListener('click', () => {
            document.getElementById("mainContainer").style.display = "none";
            document.getElementById("editpasswordmodal").style.display = "block";
            document.getElementById("editwebpage").value = password.websiteName;
            document.getElementById("editusername").value = password.userName;
            document.getElementById("editpassword").value = password.password;
        });

        passwordTableBody.appendChild(row);
    });
}

function searchPassword() {
    let query = document.getElementById("passwordSearch").value.toLowerCase().trim();
    let resultsContainer = document.getElementById("searchResults");
    resultsContainer.innerHTML = "";

    if (query === "") {
        document.getElementById("searchResultsModal").style.display = "none";
        return;
    }
    getPasswords().then(passwords => {
        let filteredResults = passwords.filter(pw =>
            pw.websiteName.toLowerCase() === query || 
            pw.userName.toLowerCase() === query
        );

        document.getElementById("searchResultsModal").style.display = filteredResults.length > 0 ? "block" : "none";

        if (filteredResults.length > 0) {
            filteredResults.forEach(password => {
                let resultItem = document.createElement("div");
                resultItem.innerHTML = `<strong>${password.websiteName}</strong><br><br> Username: ${password.userName} <br> Password: ${password.password}`;
                resultItem.classList.add("search-result-item");
                resultsContainer.appendChild(resultItem);
            });
        } else {
            resultsContainer.innerHTML = "<p>No exact matches found.</p>";
        }
    });
}

function closeSearchResults() {
    document.getElementById("searchResultsModal").style.display = "none";
}


function checkPasswordStrength () {
    let password = document.getElementById("passwordCheck");
    let power = document.getElementById("power-point");
    let point = 0;
    let value = password.value;
    let widthPower = 
        ["1%", "25%", "50%", "75%", "100%"];
    let colorPower = 
        ["#D73F40", "#DC6551", "#F2B84F", "#BDE952", "#3ba62f"];

    if (value.length >= 8) {
        let arrayTest = 
            [/[0-9]/, /[a-z]/, /[A-Z]/, /[^0-9a-zA-Z]/];
        arrayTest.forEach((item) => {
            if (item.test(value)) {
                point += 1;
            }
        });
    }
    power.style.width = widthPower[point];
    power.style.backgroundColor = colorPower[point];
};