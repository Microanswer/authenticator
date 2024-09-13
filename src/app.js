let BtnStartDom = document.querySelector(`#btn-start`);
let TextAreaDom = document.querySelector(`#textareaIn`);
let ResultsDom = document.querySelector(`#results`);
let AtipDom = document.querySelector(`.atip`);

function showTip(msg) {
    AtipDom.textContent = msg;
    AtipDom.classList.remove("hidden");
}

function hideTip() {
    AtipDom.classList.add("hidden");
}

let authenticators = [];

function getToken(key, options) {
    options = options || {}
    let epoch, time, shaObj, hmac, offset, otp
    options.period = options.period || 30
    options.algorithm = options.algorithm || "SHA-1"
    options.digits = options.digits || 6
    options.timestamp = options.timestamp || Date.now()
    key = base32tohex(key)
    epoch = Math.floor(options.timestamp / 1000.0)
    time = leftpad(dec2hex(Math.floor(epoch / options.period)), 16, "0")
    shaObj = new jsSHA(options.algorithm, "HEX")
    shaObj.setHMACKey(key, "HEX")
    shaObj.update(time)
    hmac = shaObj.getHMAC("HEX")
    offset = hex2dec(hmac.substring(hmac.length - 1))
    otp = (hex2dec(hmac.substr(offset * 2, 8)) & hex2dec("7fffffff")) + ""
    otp = otp.substr(Math.max(otp.length - options.digits, 0), options.digits)
    return otp
}

function hex2dec(s) {
    return parseInt(s, 16)
}

function dec2hex(s) {
    return (s < 15.5 ? "0" : "") + Math.round(s).toString(16)
}

function base32tohex(base32) {
    let base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
        bits = "",
        hex = ""

    base32 = base32.replace(/=+$/, "")

    for (let i = 0; i < base32.length; i++) {
        let val = base32chars.indexOf(base32.charAt(i).toUpperCase())
        if (val === -1) throw new Error("Invalid base32 character in key")
        bits += leftpad(val.toString(2), 5, "0")
    }

    for (let i = 0; i + 8 <= bits.length; i += 8) {
        let chunk = bits.substr(i, 8)
        hex = hex + leftpad(parseInt(chunk, 2).toString(16), 2, "0")
    }
    return hex
}

function leftpad(str, len, pad) {
    if (len + 1 >= str.length) {
        str = Array(len + 1 - str.length).join(pad) + str
    }
    return str
}


function Authenticator(token) {
    this.token = token;
    this.dom = this.newDom();
}

Authenticator.prototype.newDom = function () {
    let domTemplate = document.querySelector(`[data-domtpye="rowtemplate"]`);
    /**
     *
     * @type {HTMLDivElement}
     */
    let newDom = domTemplate.cloneNode(true);
    newDom.classList.remove("hidden");
    newDom.removeAttribute("data-domtype");
    newDom.querySelector(`.atoken`).textContent = this.token;
    newDom.querySelector(".aclose").addEventListener("click", this.onCloseClick.bind(this));
    return newDom;
}

Authenticator.prototype.update = function () {
    let now = new Date();

    let nowSecond = now.getSeconds();
    let z = now.getTime();
    if (0 <= nowSecond && nowSecond < 30) {
        now.setSeconds(nowSecond + (30 - nowSecond));
    } else {
        now.setSeconds(nowSecond + (60 - nowSecond));
    }
    now.setMilliseconds(0);
    let m = now.getTime();

    let percent = ((m - z) / (30 * 1000));
    let code = getToken(this.token, {timestamp: Date.now()});
    this.dom.querySelector(".acode").textContent = "动态密码：" + code;
    let rd = this.dom.querySelector(".aradial");
    rd.style.setProperty("--value",percent * 100);
    rd.textContent = Math.round(percent * 30);
}

Authenticator.prototype.onCloseClick = function () {
    this.dom.remove();
    let index = authenticators.indexOf(this);
    if (index !== -1){
        authenticators.splice(index, 1);
    }
}




BtnStartDom.addEventListener("click", function () {
    let value = TextAreaDom.value.trim() || "";
    if (!value) {
        return
    }

    try {
        getToken(value, {timestamp: Date.now()})
    }catch (err) {
        showTip("你输入的Token有误，[" + err.message +"]。");
        return;
    }

    var authenticator = new Authenticator(value);
    ResultsDom.append(authenticator.dom);
    authenticators.push(authenticator);

    TextAreaDom.value = "";
    hideTip();
});

requestAnimationFrame(function render() {

    for (let i = 0; i < authenticators.length; i++) {
        authenticators[i].update();
    }

    requestAnimationFrame(render);
});

