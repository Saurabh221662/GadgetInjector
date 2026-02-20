
# 🚀 Gadgetinjector

**Gadgetinjector** is a modern, production-ready **Frida Gadget injector for iOS 17 / iOS 18 IPAs**, designed to work seamlessly with **Objection in listen mode**.

It safely injects Frida Gadget into iOS applications while respecting Apple’s latest Mach-O loader rules, runtime hardening, and code-signing constraints — making it ideal for **professional iOS security testing and reverse engineering**.

> ⚠️ For authorized security research and testing only

---

## ✨ Features

- 🔍 Automatic Frida version detection  
- 📦 Downloads and injects the **matching Frida Gadget**  
- 🧩 Architecture compatibility checks (`arm64 / arm64e`)  
- 🔗 Objection-ready **listen mode** configuration  
- 🛡️ iOS 17 / 18 safe Mach-O injection  
- 🧹 Cleans signing artifacts for predictable re-signing  
- 🖥️ Professional CLI with `--version` and `--about`

---

## 🔍 How Gadgetinjector Works

1. Securely extracts the IPA  
2. Identifies the correct app executable  
3. Detects the installed Frida version  
4. Validates Gadget availability on GitHub  
5. Ensures architecture compatibility  
6. Injects Frida Gadget using `@rpath`  
7. Generates Objection-friendly configuration  
8. Prepares IPA for re-signing  

---

## 🧰 Prerequisites

### 🐍 Python Dependencies

Install the required Python packages:

```bash
pip install lief frida frida-tools pymobiledevice3
````
| Dependency        | Purpose                                   |
| ----------------- | ----------------------------------------- |
| `lief`            | Mach-O parsing & injection (**required**) |
| `frida`           | Frida version detection                   |
| `frida-tools`     | Frida CLI compatibility                   |
| `pymobiledevice3` | USB port forwarding                       |

---

### 🛠 System Tools

Install Xcode command-line tools:

```bash
xcode-select --install
```

---

### 📱 Optional Tools (For Installing IPAs)

You will need **one** of the following tools to install the re-signed IPA:

* **Sideloadly** (GUI – easiest)
* **AltStore**
* **Xcode**
* **ios-deploy**

---

## 🚀 Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/Gadgetinjector.git
cd Gadgetinjector
```

Make the script executable:

```bash
chmod +x gadget_injector.py
```

---

## ▶️ Usage

### Basic Injection

```bash
python3 gadget_injector.py MyApp.ipa
```

**Output:**

```text
MyApp-frida-listen.ipa
```

---

### Specify Frida Version

```bash
python3 gadget_injector.py MyApp.ipa --frida-version 17.6.2
```

---

### Target Specific App (Multi-IPA)

```bash
python3 gadget_injector.py MyApp.ipa --bundle-id com.example.app
```

---

### Debug Mode

```bash
python3 gadget_injector.py MyApp.ipa --debug
```

---

### Suppress Banner (CI / Automation)

```bash
python3 gadget_injector.py MyApp.ipa --no-banner
```

---

## 📲 After Injection (Required Steps)

### 1️⃣ Re-sign the IPA

Choose **one** method:

* **Sideloadly** (GUI – easiest)
* **AltStore**
* **Xcode**
* CLI tools (`zsign`, `isign`, `rcodesign`)

> 🔐 Sign **all embedded dylibs** with the **same Team ID**
> ❌ **Do NOT** add entitlements to `FridaGadget.dylib`

---

### 2️⃣ Launch App (Paused – Recommended)

```bash
xcrun devicectl device process launch \
  --device <UDID> \
  --start-stopped <bundle-id>
```

---

### 3️⃣ Forward Frida Port (USB)

```bash
pymobiledevice3 usbmux forward 27042 27042
```

---

### 4️⃣ Connect with Objection

```bash
Objection -g bundleid explore```

Or using Frida CLI:

```bash
frida -H 127.0.0.1:27042 -n MyApp
```
