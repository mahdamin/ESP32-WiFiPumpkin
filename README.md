# WP3: Embedded Systems & Security Research

A sophisticated embedded systems project developed using the ESP-IDF (Espressif IoT Development Framework). This project serves as an educational deep-dive into low-level networking, specifically focusing on the implementation and analysis of the WPA Supplicant and Wi-Fi stack.

## Table of Contents

* [Overview](https://www.google.com/search?q=%23overview)
* [Tech Stack](https://www.google.com/search?q=%23tech-stack)
* [Project Structure](https://www.google.com/search?q=%23project-structure)
* [Getting Started](https://www.google.com/search?q=%23getting-started)
* [Future Enhancements](https://www.google.com/search?q=%23future-enhancements)

---

## Overview

WP3 is an academic exploration of wireless protocols and embedded security. By leveraging the ESP32's native Wi-Fi capabilities and the robust ESP-IDF environment, this project demonstrates:

* **Protocol Management:** Custom handling of the wpa_supplicant layer.
* **Memory Efficiency:** Optimized partition management using nvs_flash.
* **Low-Level Porting:** Hardware abstraction and ROM interfacing for the ESP32 architecture.

## Tech Stack

* **Framework:** [ESP-IDF](https://www.google.com/search?q=https://docs.espressif.com/projects/esp-idf/en/latest/esp32/index.html)
* **Language:** C / C++
* **Build System:** CMake & Ninja
* **Core Libraries:** * wpa_supplicant (Wi-Fi Security)
* nvs_flash (Non-volatile storage)
* bootloader_support



## Project Structure

```text
WP3/
├── build/                  # Compiled binaries and build artifacts
├── .vscode/                # IDE-specific configurations
├── main/                   # Application entry point and core logic
└── components/             # Modular system components (Wi-Fi, NVS, etc.)

```

## Getting Started

### Prerequisites

1. Install the [ESP-IDF Toolchain](https://www.google.com/search?q=https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/index.html).
2. Ensure you have an ESP32 development board connected.

### Installation & Build

1. **Clone the repository:**
```bash
git clone https://github.com/yourusername/WP3.git
cd WP3

```


2. **Set the target:**
```bash
idf.py set-target esp32

```


3. **Build and Flash:**
```bash
idf.py build flash monitor

```



## Educational Disclaimer

This project is for educational purposes only. It is designed to help students and researchers understand the inner workings of wireless security protocols. Always ensure you have permission before testing on any network.
