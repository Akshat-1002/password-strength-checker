(function () {

  /* ===============================
     SHA-1 HASH (for breach check)
     =============================== */
  async function sha1(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest("SHA-1", msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, "0")).join("").toUpperCase();
  }

 
  function calculateEntropy(password) {
    let charset = 0;
    if (/[a-z]/.test(password)) charset += 26;
    if (/[A-Z]/.test(password)) charset += 26;
    if (/[0-9]/.test(password)) charset += 10;
    if (/[^A-Za-z0-9]/.test(password)) charset += 32;
    if (!charset) return 0;
    return Math.round(password.length * Math.log2(charset));
  }

  
  async function checkBreach(password) {
    const hash = await sha1(password);
    const prefix = hash.slice(0, 5);
    const suffix = hash.slice(5);

    const response = await fetch(
      `https://api.pwnedpasswords.com/range/${prefix}`
    );
    const text = await response.text();
    return text.includes(suffix);
  }

 
  function init(input) {

    const widget = document.createElement("div");
    widget.className = "psw-widget";
    widget.innerHTML = `
      <div class="psw-bar"><div class="psw-fill"></div></div>
      <div class="psw-meta">
        <span class="psw-strength"></span>
        <span class="psw-entropy"></span>
      </div>
      <ul class="psw-suggestions"></ul>
    `;

    input.after(widget);

    const fill = widget.querySelector(".psw-fill");
    const strengthText = widget.querySelector(".psw-strength");
    const entropyText = widget.querySelector(".psw-entropy");
    const suggestions = widget.querySelector(".psw-suggestions");

    let breachTimeout;
    let lastPassword = "";

    input.addEventListener("input", async () => {
      const password = input.value;
      suggestions.innerHTML = "";

      if (!password) {
        fill.style.width = "0%";
        strengthText.textContent = "";
        entropyText.textContent = "";
        return;
      }

     
      const entropy = calculateEntropy(password);
      entropyText.textContent = `${entropy} bits`;
      fill.style.width = Math.min((entropy / 80) * 100, 100) + "%";

      let strengthLevel = "weak";

      if (entropy < 40) {
        fill.style.background = "#ef4444";
        strengthText.textContent = "Weak";
      } else if (entropy < 60) {
        fill.style.background = "#f59e0b";
        strengthText.textContent = "Medium";
        strengthLevel = "medium";
      } else {
        fill.style.background = "#22c55e";
        strengthText.textContent = "Strong";
        strengthLevel = "strong";
      }

     
      if (password.length < 12)
        suggestions.innerHTML += `<li>Add ${12 - password.length} more characters</li>`;
      if (!/[A-Z]/.test(password))
        suggestions.innerHTML += `<li>Add an uppercase letter</li>`;
      if (!/[0-9]/.test(password))
        suggestions.innerHTML += `<li>Add a number</li>`;
      if (!/[^A-Za-z0-9]/.test(password))
        suggestions.innerHTML += `<li>Add a special symbol</li>`;

     
      clearTimeout(breachTimeout);
      lastPassword = password;

      breachTimeout = setTimeout(async () => {
        const breached = await checkBreach(password);

      
        if (password !== lastPassword) return;

        if (breached) {
          suggestions.innerHTML += `
            <li style="color:#b91c1c">
              ⚠ This password has appeared in known data breaches. Do NOT use it.
            </li>
          `;
        } else if (strengthLevel === "strong") {
         
          suggestions.innerHTML += `
            <li style="color:#065f46">
              💡 Consider saving this password in a password manager
              (e.g., Bitwarden, 1Password, Google Password Manager)
              to avoid reuse.
            </li>
          `;
        }
      }, 600);
    });
  }

  
  document
    .querySelectorAll("[data-password-strength]")
    .forEach(init);

})();
