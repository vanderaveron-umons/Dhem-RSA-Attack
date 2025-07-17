# Dhem et al. RSA Timing Attack Implementation

A Python implementation of the Dhem et al. timing attack against RSA, originally published in "A Practical Implementation of the Timing Attack" (2000). DOI: [10.1007/10721064_15](https://doi.org/10.1007/10721064_15)

## Overview

This repository provides an educational implementation of the timing attack methodology described by Dhem et al., which improves upon Kocher's original timing attack by using binary oracles and targeting Montgomery multiplication reduction steps.

## Features

- Vulnerable RSA implementation with configurable timing leaks
- Two-oracle attack targeting squaring operations  
- Experimental framework for systematic evaluation with parallel execution of tests
- CSV output for timing and success rate results

## Installation

```bash
git clone https://github.com/vanderaveron-umons/Dhem-RSA-Attack.git
cd dhem-rsa-attack
pip install -r requirements.txt
```

## ⚠️ Insecure RSA implementation
The provided RSA implementation is intentionally insecure and contains vulnerabilities.
It is designed for educational purposes only and **_must not_** be used in real-world applications.

This code is for educational and research purposes only. 

## License
MIT License - see LICENSE file for details.