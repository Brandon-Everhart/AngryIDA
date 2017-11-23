# AngryIDA

![pylint Score](https://mperlet.de/pybadge/badges/9.61.svg) [![standard-readme compliant](https://img.shields.io/badge/readme%20style-standard-brightgreen.svg)](https://github.com/RichardLitt/standard-readme)  ![conduct](https://img.shields.io/badge/code%20of%20conduct-contributor%20covenant-brightgreen.svg) 

| Table of Contents |
|-------------------|
|[Background](#background)|
|[Install](#install-tips)|
|[Usage](#usage)|
|[TODO](#todo)|
|[Standards](#standards)|
|[Maintainers](#maintainers)|
|[Contribute](#contribute)|
|[License](#license)|        

## Background

The goal of this plug-in is to integrate the use of the angr binary analysis framework into IDA Pro. 

## Install Tips

_**NOTE: This section only describes the process of installation and setup in our specific environment.**_

**1. Windows 7 64 bit Virtual Machine?**
- Yes: Cool you are in the same place as us.
- No: Well.... no promises. 

**2. IDA Pro 6.9?**
- Yes: Install Microsoft Visual C++ 2015 or newer and update the .NET Framework.
- No: Install IDA 6.9 then return here.

**3. IDA Python Plug-In Working?**
- Yes: Continue to the next step.
- No: Sorry, we did not have this problem.

**4. Python 2.7 is installed?**
- Yes: Keep going.
- No: There are many resources online for installing python 2.7 on virtually every system.

**5. Python package manager pip is installed?**
- Yes: Awesome, one step closer.
- No: Installing pip is straightforward and help can be found online.

**6. angr is installed and working?**
- Yes: You got off easy! Skip to the next step.
- No: Try this...
    + Install Microsoft Visual Studio 2017 (Really you just need the developer command prompt)
    + Install the Microsoft Visual C++ Compiler for Python 2.7
    + Inside the Microsoft Visual Studio Developers Command Prompt run the following commands:
        * pip install -I --pre --no-use-wheel capstone-windows
        * pip install pyvex
        * pip install unicorn
        * pip install simuvex
        * pip install angr

**7. Download this repository (At least the file AngryIDA.py)?**
- Yes: You are ready to use AngryIDA!
- No: Why not?

## Usage

## TODO

## Standards

* [Standard Readme](https://github.com/RichardLitt/standard-readme)
* [Contributor Covenant](https://contributor-covenant.org/version/1/3/0/) Code of Conduct.
* [Pylint](https://www.pylint.org/)

## Maintainers

* [Brandon Everhart](https://github.com/Brandon-Everhart)
* [Taylor Shields](https://github.com/Taylor-Shields)

## Contribute

Any and all contributions are appertained! [Open an issue](https://github.com/Brandon-Everhart/AngryIDA/issues/new) or submit PRs.

## Related Efforts

* [Ponce](https://github.com/illera88/Ponce)

## License
[GNU General Public License v3.0](LICENSE)