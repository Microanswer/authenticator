// @ts-nocheck

/**
 *
 * @param  {"top_center"|"top_right"|"top_left"|"center_center"|"center_left"|"center_right"|"bottom_left"|"bottom_center"|"bottom_right"} position
 * @param  {HTMLElement} appendTo
 * @constructor
 */
function ToastManager(position, appendTo = document.body) {
    this.$el = document.createElement("div");
    this.$el.style.zIndex = "99999";
    this.$el.style.display = "block";
    this.$el.classList.add("toast", "fixed", "flex", "flex-col", "gap-0");
    let [vert, horn] = position.split(/[\-_ ,:]/);

    let vertClass = {
        "top": "toast-top",
        "center": "toast-middle",
        "bottom": "toast-bottom"
    }[vert];
    this.$el.classList.add(vertClass);

    let hornClass = {
        "left": "toast-start",
        "center": "toast-center",
        "right": "toast-end"
    }[horn];
    this.$el.classList.add(hornClass);

    /**
     *
     * @type {{[id: string]: Toast}}
     */
    this.toasts = {};
    appendTo.append(this.$el);
}

/**
 * 添加一个土司提示。
 * @param toast {Toast}
 */
ToastManager.prototype.addToast = function (toast) {
    this.$el.style.display = "flex";
    let id = toast.id;
    this.toasts[id] = toast;
    this.$el.append(toast.$el);
}

ToastManager.prototype.removeToast = function (toast) {
    // console.log("移除toast：" + toast.id, this.toasts);
    this.toasts[toast.id]?.hide();
    delete this.toasts[toast.id];

    if (Object.values(this.toasts).length <= 0) {
        this.$el.style.display = "none";
        // console.log("移除了toast：" + toast.id, this.toasts);
    }
}

/**
 * 构造一个土司提示。
 * @param {{
 *     type: "success" | "warning" | "error" | "info" | "default",
 *     message: string,
 *     position: "top_center"|"top_right"|"top_left"|"center_center"|"center_left"|"center_right"|"bottom_left"|"bottom_center"|"bottom_right",
 *     timeout: number
 * }?} options
 * @constructor
 */
function Toast(options) {
    this.options = options || {};
    this.id = String(Date.now()) + String(Math.random());

    this.options.root = this.options.root || document.body;
    if (typeof this.options.timeout === "undefined") {
        this.options.timeout = 3000;
    }
    if (typeof this.options.type === "undefined") {
        this.options.type = "default";
    }
    if (typeof this.options.message === "undefined") {
        this.options.message = "未设定提示内容";
    }
    if (typeof this.options.position === "undefined") {
        this.options.position = "top_center";
    }

    this.destroyed = false;

    Toast__createDom.call(this);
}
Toast.prototype.show = function (animTime = 400) {

    this.__getToastManager().addToast(this);

    let transform = this.__getFromTransform();
    this.$el.style.transform = transform;
    this.$el.style.transitionDuration = `${animTime}ms`;
    // this.$el.style.transitionProperty = "transform, opacity";
    this.$el.style.opacity = "0";

    requestAnimationFrame(() => {
        this.$el.style.opacity = "1";
        this.$el.style.transform = "translate(0,0)";
    });

    this.hideTaskId = setTimeout(() => {
        this.hide();
    }, this.options.timeout);
}
Toast.prototype.setMessage = function (message) {
    this.$el.querySelector("span").textContent = message;
}

/**
 * 返回一个可以用于 显示出toast的开始动画的初始transform值，及隐藏动画的结束transform值。
 * @returns {string}
 * @private
 */
Toast.prototype.__getFromTransform = function () {
    let transform = ""
    if (this.options.position.endsWith("left")) {
        transform = `translateX(-${this.$el.getBoundingClientRect().width + 20}px)`;
    } else if (this.options.position.endsWith("right")) {
        transform = `translateX(${this.$el.getBoundingClientRect().width + 20}px)`;
    } else if (this.options.position.startsWith("top")) {
        transform = `translateY(-${this.$el.getBoundingClientRect().height + 20}px)`;
    } else if (this.options.position.startsWith("bottom")) {
        transform = `translateY(${this.$el.getBoundingClientRect().height + 20}px)`;
    }
    return transform;
}

Toast.prototype.__getToastManager = function () {
    let TMS = this.options.root["TMS"] = this.options.root["TMS"] || new Map();
    this.toastManager = TMS[this.options.position];

    if (!this.toastManager) {
        this.toastManager = new ToastManager(this.options.position, this.options.root);
        TMS[this.options.position] = this.toastManager;
    }

    return this.toastManager;
}

Toast.prototype.hide = function (fn, animDur = 400) {
    if (this.destroyed) return;
    this.destroyed = true;

    if (typeof animDur === "function") {
        let ov = animDur;
        animDur = fn;
        fn = ov;
    }
    if (typeof fn === "number") {
        animDur = fn;
        fn = () => { };
    }

    let transform = this.__getFromTransform();
    let height = this.$el.clientHeight + "px";
    this.$el.style.position = "relative";
    this.$el.style.height = height;
    this.$el.style.width = this.$el.clientWidth + "px";

    // 有可能，这个toast的显示动画还没执行完成，此时要进行隐藏了。
    requestAnimationFrame(() => {

        this.$el.style.overflow = "visible";
        this.$el.style.transitionDuration = `${animDur}ms`;
        this.$el.style.transform = transform;
        this.$el.style.height = "0";
        this.$el.style.opacity = "0";
        this.$el.style.transitionProperty = "top, opacity, transform, height";


        let transEnd = () => {
            this.$el.removeEventListener('transitionend', transEnd);
            this.$el.remove();
            fn && fn();
            if (typeof this.hideTaskId !== "undefined") {
                clearTimeout(this.hideTaskId);
            }
            this.__getToastManager().removeToast(this);
        };
        this.$el.addEventListener('transitionend', transEnd);
    });
}

function Toast__createDom() {
    let alertDom = document.createElement("div");
    let alertClass = {
        "default": "alert-default",
        "info": "alert-info",
        "warning": "alert-warning",
        "success": "alert-success",
        "error": "alert-error"
    }[this.options.type];
    alertDom.classList.add("alert", "border", alertClass);

    if (this.options.type === "default") {
        alertDom.innerHTML = `
    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" class="stroke-info h-6 w-6 shrink-0">
    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
  </svg>
  <span>${this.options.message}</span>
  <div class="px-4">
    <button class="close-toast btn btn-sm btn-circle btn-ghost absolute right-2 top-2">✕</button>
  </div>
    `
    }
    else if (this.options.type === "info") {
        alertDom.innerHTML = `
        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" class="h-6 w-6 shrink-0 stroke-current">
    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
  </svg>
  <span>${this.options.message}</span>
  <div class="px-4">
    <button class="close-toast btn btn-sm btn-circle btn-ghost absolute right-2 top-2">✕</button>
  </div>
        `
    }
    else if (this.options.type === "warning") {
        alertDom.innerHTML = `
        <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 shrink-0 stroke-current" fill="none" viewBox="0 0 24 24">
    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
  </svg>
  <span>${this.options.message}</span>
  <div class="px-4">
    <button class="close-toast btn btn-sm btn-circle btn-ghost absolute right-2 top-2">✕</button>
  </div>
        `
    }
    else if (this.options.type === "success") {
        alertDom.innerHTML = `
        <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 shrink-0 stroke-current" fill="none" viewBox="0 0 24 24">
    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
  </svg>
  <span>${this.options.message}</span>
  <div class="px-4">
    <button class="close-toast btn btn-sm btn-circle btn-ghost absolute right-2 top-2">✕</button>
  </div>
        `
    }
    else if (this.options.type === "error") {
        alertDom.innerHTML = `
            <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 shrink-0 stroke-current" fill="none" viewBox="0 0 24 24">
    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" />
  </svg>
  <span>${this.options.message}</span>
  <div class="px-4">
    <button class="close-toast btn btn-sm btn-circle btn-ghost absolute right-2 top-2">✕</button>
  </div>
        `
    }

    alertDom.querySelector(`.close-toast`).addEventListener('click', Toast__onCloseClick.bind(this));
    alertDom.classList.add("mb-2");

    let contianer = document.createElement("div");
    contianer.appendChild(alertDom);

    this.$el = contianer;
}

function Toast__onCloseClick() {
    this.hide();
}

/**
 *
 * @param options {{
 *     root: HTMLElement?,
 *     type: "success" | "warning" | "error" | "info" | "default",
 *     message: string,
 *     position: "top_center"|"top_right"|"top_left"|"center_center"|"center_left"|"center_right"|"bottom_left"|"bottom_center"|"bottom_right",
 *     timeout: number
 * }?}
 * @constructor
 */
Toast.ShowToast = function (options) {
    let t = new Toast(options);
    t.show();
    return t;
}
/**
 *
 * @param options {{
 *     type: "success" | "warning" | "error" | "info" | "default",
 *     message: string,
 *     position: "top_center"|"top_right"|"top_left"|"center_center"|"center_left"|"center_right"|"bottom_left"|"bottom_center"|"bottom_right",
 *     timeout: number
 * }?}
 * @returns {Toast}
 * @constructor
 */
export const ShowToast = Toast.ShowToast;